import asyncio
from bson import ObjectId
from backend.routes.files import files_collection

async def check_files():
    # Check the specific file IDs mentioned
    file_ids = ['69c777ebaf94684d63c5361b', '69c765dd20ca22c64a0bfb7d']
    
    for file_id in file_ids:
        try:
            if ObjectId.is_valid(file_id):
                file_doc = await files_collection().find_one({'_id': ObjectId(file_id)})
                print(f'File {file_id}:')
                if file_doc:
                    print(f'  Found: {file_doc.get("file_name", "unknown")}')
                    print(f'  Status: {file_doc.get("status")}')
                    print(f'  S3 Key: {file_doc.get("s3_key")}')
                    print(f'  S3 Uploaded: {file_doc.get("s3_uploaded")}')
                    print(f'  MIME: {file_doc.get("mime_type")}')
                else:
                    print('  NOT FOUND in MongoDB')
                print()
            else:
                print(f'Invalid ObjectId format: {file_id}')
        except Exception as e:
            print(f'Error checking {file_id}: {e}')

if __name__ == "__main__":
    asyncio.run(check_files())
