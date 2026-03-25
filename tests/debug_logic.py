import json

# Simulate the exact error handling logic
data = {'detail': 'too many upload initialization requests'}

print("Testing error handling logic:")
print(f"Data: {data}")
print(f"Has 'detail': {'detail' in data}")
print(f"Detail value: {data.get('detail', '')}")
print(f"Is string: {isinstance(data['detail'], str)}")
print()

# Test rate limiting check
rate_limit_check = "too many upload initialization requests" in data.get("detail", "")
print(f"Rate limiting check: {rate_limit_check}")
print()

# Test isinstance check  
isinstance_check = isinstance(data["detail"], str)
print(f"Isinstance check: {isinstance_check}")
print()

if "detail" in data:
    print("In 'detail' condition")
    if "too many upload initialization requests" in data.get("detail", ""):
        print("  Rate limiting condition matched!")
    elif isinstance(data["detail"], str):
        print("  Isinstance condition matched!")
        try:
            nested_data = json.loads(data["detail"])
            print(f"  Parsed JSON: {nested_data}")
        except:
            print("  JSON parsing failed")
    else:
        print("  Else condition matched")
