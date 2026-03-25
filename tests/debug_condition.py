# Debug the actual condition
data = {'detail': 'content_type/mime_type is required and cannot be empty'}

print(f"Detail value: {repr(data.get('detail', ''))}")
print(f"Lowercase: {repr(data.get('detail', '').lower())}")
print(f"Contains 'content_type': {'content_type' in data.get('detail', '').lower()}")
print(f"Contains 'too many': {'too many upload initialization requests' in data.get('detail', '')}")

# Test the full condition
condition1 = "too many upload initialization requests" in data.get("detail", "")
condition2 = "content_type" in data.get("detail", "").lower()
condition3 = condition1 or condition2

print(f"Condition 1 (rate limiting): {condition1}")
print(f"Condition 2 (content_type): {condition2}")
print(f"Combined condition: {condition3}")
