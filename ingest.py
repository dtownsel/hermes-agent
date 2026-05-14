import os
import io
import json
import re
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import pymupdf4llm
from docx import Document
from pptx import Presentation
import pandas as pd

creds = Credentials.from_authorized_user_file(os.path.expanduser('~/.hermes/google_token.json'), ['https://www.googleapis.com/auth/drive'])
service = build('drive', 'v3', credentials=creds)

folders = [
    {"folder_id": "1UFvdZkhmp_FUz2qRcUQ7LhSp5Co5QWWu", "topic_tag": "cco-guidance"},
    {"folder_id": "1nsC8bkBRdxqhwjeLfLQkUQPeOg1eMnXz", "topic_tag": "crisis-comms"},
    {"folder_id": "15nlhX88L-VmVTNA7czYix0h07WWQfkhA", "topic_tag": "public-relations"},
    {"folder_id": "1U0pg6RDqmlmBi0CyDR6vImexsAVd1dDg", "topic_tag": "social-media"},
    {"folder_id": "1DcqAVZXtjjCXCVXg9FzN6Gtsu2bFA30z", "topic_tag": "change-management"},
    {"folder_id": "1Q3ROXykhmgdqYdM6ruFrurtLeCcL33wW", "topic_tag": "ai-architecture"},
    {"folder_id": "1eTX9oBGDlBKU3hcYs6zA_TKvD7wZsaTG", "topic_tag": "martech-stack"},
    {"folder_id": "1KGNzRxBPFoa6APsNzdtKQQkD_V7C_hdR", "topic_tag": "martech-stack/ignition-guide"}
]

exclude_file_ids = {"19cP-K4dreCmJY_fHaqw3Jzc6vGgZgUl8", "1zJimlZRTv45xocAhZfHPDtd4OkAim5B5"}
exclude_mime_types = {"application/octet-stream", "application/zip"}
exclude_patterns = [".DS_Store"]

out_dir = os.path.expanduser("~/.hermes/gartner_ingest")
os.makedirs(out_dir, exist_ok=True)
tmp_dir = os.path.expanduser("~/.hermes/gartner_tmp")
os.makedirs(tmp_dir, exist_ok=True)

processed_files = []
duplicates_skipped = []
errors_encountered = []
seen_sizes = {} # to check byte duplicates within same folder
cross_folder_file_809957_size = 527368

def get_gartner_doc_id(filename):
    m = re.search(r'_(\d{6})(?:_ndx)?\.(pdf|pptx|xlsx|docx)$', filename)
    return m.group(1) if m else None

def get_format(filename):
    if filename.endswith(('.xlsx', '.xlsm')): return 'tool'
    if filename.endswith('.pdf') and '_ndx.pdf' in filename: return 'report'
    if filename.endswith('.pptx') or filename.endswith('.docx'): return 'template'
    return 'report' # default

for f_info in folders:
    folder_id = f_info["topic_tag"]
    q = f"'{f_info['folder_id']}' in parents and trashed = false"
    try:
        results = service.files().list(q=q, fields="files(id, name, mimeType, size, modifiedTime)").execute()
        items = results.get('files', [])
    except Exception as e:
        print(f"Error fetching {f_info['folder_id']}: {e}")
        continue
    
    seen_sizes_in_folder = {}
    
    for item in items:
        file_id = item['id']
        name = item['name']
        mime = item['mimeType']
        size = item.get('size')
        if not size: size = 0
        size = int(size)
        
        if file_id in exclude_file_ids: continue
        if mime in exclude_mime_types: continue
        if any(p in name for p in exclude_patterns): continue
        
        # Deduplication cross folder
        if size == cross_folder_file_809957_size and "809957" in name:
            if "809957" not in seen_sizes:
                seen_sizes["809957"] = True
                topic_tags = ["crisis-comms", "change-management"]
            else:
                duplicates_skipped.append(file_id)
                continue
        else:
            topic_tags = [f_info['topic_tag']]
            
            # Intra folder deduplication
            if size in seen_sizes_in_folder:
                duplicates_skipped.append(file_id)
                continue
            seen_sizes_in_folder[size] = True

        sanitized_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)
        md_name = os.path.splitext(sanitized_name)[0] + ".md"
        out_path = os.path.join(out_dir, md_name)
        
        try:
            request = service.files().get_media(fileId=file_id)
            tmp_path = os.path.join(tmp_dir, sanitized_name)
            with io.FileIO(tmp_path, 'wb') as fh:
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()
            
            content = ""
            if name.endswith('.pdf'):
                content = pymupdf4llm.to_markdown(tmp_path)
            elif name.endswith('.docx'):
                doc = Document(tmp_path)
                content = "\\n".join([p.text for p in doc.paragraphs])
            elif name.endswith('.pptx'):
                prs = Presentation(tmp_path)
                for slide in prs.slides:
                    for shape in slide.shapes:
                        if hasattr(shape, "text"):
                            content += shape.text + "\\n"
            elif name.endswith('.xlsx') or name.endswith('.xlsm'):
                df = pd.read_excel(tmp_path)
                content = df.to_markdown()
            else:
                content = f"Unknown format or could not extract text for {name}"
                
            doc_id = get_gartner_doc_id(name)
            doc_format = get_format(name)
            
            processed_files.append({
                "path": out_path,
                "title": name,
                "doc_type": "gartner_research",
                "content": content[:100000], # truncate to 100K chars max
                "frontmatter": {
                    "source": "gartner",
                    "topic": topic_tags,
                    "format": doc_format,
                    "modified_time": item.get('modifiedTime'),
                    "gartner_doc_id": doc_id,
                    "original_file_id": file_id
                }
            })
            
            # Write the file directly instead of storing all in memory just in case, but we also save the meta
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(content)

        except Exception as e:
            errors_encountered.append({"file_id": file_id, "error": str(e)})

summary = {
    "total": len(processed_files),
    "processed_files": processed_files,
    "duplicates_skipped": duplicates_skipped,
    "errors_encountered": errors_encountered
}

with open(os.path.join(out_dir, 'summary.json'), 'w') as f:
    json.dump(summary, f)

print(json.dumps({"status": "ready", "total": len(processed_files), "dups": len(duplicates_skipped), "errs": len(errors_encountered)}))
