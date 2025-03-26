import random
import argparse
import uuid

def generate_android_device_id():
    """Generate a 64-bit Android device ID with 10 digits and 6 a-f characters (lowercase)."""
    # Generate a 64-bit number
    device_id = random.getrandbits(64)

    # Convert the 64-bit number to a hexadecimal string
    hex_device_id = f"{device_id:016x}"

    # Ensure the string contains 10 numeric characters (0-9) and 6 a-f characters
    digits = [random.choice('0123456789') for _ in range(10)]  # 10 digits
    hex_chars = [random.choice('abcdef') for _ in range(6)]  # 6 hexadecimal characters (a-f)
    
    # Combine the digits and characters, shuffle them and form a valid device ID
    combined = digits + hex_chars
    random.shuffle(combined)  # Shuffle the list of digits and hex chars
    
    # Ensure the final length is 16 characters (10 digits + 6 hex chars)
    final_device_id = ''.join(combined)
    
    return final_device_id  # Return the ID in lowercase

def generate_ios_address():
    """Generate a random ios address-like string (UUID format)."""
    # Generate a random UUID and remove the hyphens, since UUID is used as a ios-like address
    ios_address = uuid.uuid4().hex.upper()
    return ios_address

def generate_multiple_device_ids(count, device_type="android"):
    """Generate a specified number of device IDs (either 'android' or 'ios')."""
    if device_type == "android":
        return [generate_android_device_id() for _ in range(count)]
    elif device_type == "ios":
        return [generate_ios_address() for _ in range(count)]
    else:
        raise ValueError("Invalid device type. Choose 'android' or 'ios'.")

def main():
    # Set up argparse to handle command-line arguments
    parser = argparse.ArgumentParser(description="Generate random device IDs (Android or ios).")
    parser.add_argument("count", type=int, help="Number of device IDs to generate")
    parser.add_argument("--type", choices=["android", "ios"], default="android", help="Specify the type of device ID to generate (android or ios).")
    
    args = parser.parse_args()
    
    # Generate the requested number of device IDs based on the device type
    device_ids = generate_multiple_device_ids(args.count, device_type=args.type)
    
    # Print the generated IDs
    for device_id in device_ids:
        print(device_id)

if __name__ == "__main__":
    main()