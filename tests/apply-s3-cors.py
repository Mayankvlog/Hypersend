#!/usr/bin/env python3
"""
Script to apply S3 CORS configuration for Flutter Web compatibility
"""

import json
import boto3
from botocore.exceptions import ClientError

def apply_s3_cors():
    """Apply CORS configuration to S3 bucket"""
    
    # Load CORS configuration
    with open('tests/s3-cors-configuration.json', 'r') as f:
        cors_config = f.read()
    
    try:
        # Initialize S3 client
        s3 = boto3.client('s3')
        
        # Get bucket name from settings or use default
        bucket_name = 'zaply-object-storage-781953767677-us-east-1-an'
        
        print(f"🔧 Applying CORS configuration to bucket: {bucket_name}")
        
        # Apply CORS configuration
        s3.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration=json.loads(cors_config)
        )
        
        print("✅ S3 CORS configuration applied successfully!")
        
        # Verify the configuration
        print("🔍 Verifying CORS configuration...")
        response = s3.get_bucket_cors(Bucket=bucket_name)
        print("✅ CORS configuration verified:")
        print(json.dumps(response['CORSRules'], indent=2))
        
    except ClientError as e:
        print(f"❌ Error applying S3 CORS configuration: {e}")
        print("💡 Make sure:")
        print("   - AWS credentials are properly configured")
        print("   - You have permission to modify bucket CORS")
        print("   - Bucket name is correct")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🚀 Applying S3 CORS configuration for Flutter Web...")
    success = apply_s3_cors()
    
    if success:
        print("\n🎉 S3 CORS configuration completed successfully!")
        print("\n📋 Configuration Summary:")
        print("   ✅ Allowed origins: https://zaply.in.net, http://localhost:3000, http://localhost:8080, http://localhost:8000")
        print("   ✅ Allowed methods: GET, HEAD, PUT")
        print("   ✅ Allowed headers: *")
        print("   ✅ Expose headers: Content-Disposition, Content-Length, Content-Type")
        print("   ✅ Max age: 3600 seconds")
    else:
        print("\n❌ Failed to apply S3 CORS configuration")
        print("Please check the error messages above and try again")
