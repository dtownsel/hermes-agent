import os
import sys
import json

sys.path.insert(0, '/Users/dillon/.hermes/hermes-agent')

from model_tools import handle_function_call, discover_builtin_tools
from tools.mcp_tool import discover_mcp_tools
from tools.registry import registry

def run():
    print("Discovering tools...")
    discover_builtin_tools()
    discover_mcp_tools()
    
    tools = registry.get_all_tool_names()
    print("Available tools:", tools[:10], "... mcp_reid_v7_write_document available?", "mcp_reid_v7_write_document" in tools)

    with open('/Users/dillon/.hermes/gartner_ingest/summary.json', 'r') as f:
        summary = json.load(f)

    processed_files = summary.get('processed_files', [])
    print(f"Loaded {len(processed_files)} files to ingest.")
    
    success = 0
    errors = []
    
    for i, file in enumerate(processed_files):
        print(f"Ingesting [{i+1}/{len(processed_files)}]: {file['title']}")
        
        try:
            with open(file['path'], 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            errors.append(f"Failed to read {file['path']}: {e}")
            continue

        frontmatter = file['frontmatter']
        path_pattern = f"30-reference/gartner/{frontmatter['topic'][0]}/{os.path.basename(file['path'])}"
        
        args = {
            "path": path_pattern,
            "title": file['title'],
            "doc_type": "gartner_research",
            "content": content,
            "frontmatter": frontmatter
        }
        
        try:
            res = handle_function_call("mcp_reid_v7_write_document", args, task_id="gartner_ingest")
            print(f" Result: {str(res)[:100]}...")
            success += 1
        except Exception as e:
            print(f" Error: {e}")
            errors.append(f"Ingest failed for {file['title']}: {e}")

    print(f"\\nIngestion complete: {success} successes, {len(errors)} errors.")
    
if __name__ == "__main__":
    run()