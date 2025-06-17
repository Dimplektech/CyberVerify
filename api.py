from flask import Flask, request, jsonify, render_template
import requests
import re
import os
from dotenv import load_dotenv
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    HttpUrl,
    ValidationError,
)
import urllib.parse

# Define the path to the .env file
base_dir = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(base_dir, ".env")

# Try to load environment variables using python-dotenv
load_dotenv(env_path)

# Load environment variables - Fix the assignment issue
try:
    # Try direct file loading if environment variables aren't working
    with open(env_path, "r") as f:
        env_content = f.read().strip()
        for line in env_content.split("\n"):
            if line.startswith("VIRUSTOTAL_API_KEY="):
                VIRUSTOTAL_API_KEY = line.split("=", 1)[1].strip()
                break
        else:
            # Key not found in file
            VIRUSTOTAL_API_KEY = None
except Exception as e:
    print(f"Error reading .env file: {str(e)}")
    VIRUSTOTAL_API_KEY = None

# Fallback to environment variable if file reading failed
if not VIRUSTOTAL_API_KEY:
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

print(f"API key loaded: {bool(VIRUSTOTAL_API_KEY)}")


# Initialize Flask application
app = Flask(__name__)


# memory storage
items = {}
next_id = 1


class DomainRequest(BaseModel):
    domain: str = Field(..., description="Domain name to check")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v):
        if len(v) > 255:
            raise ValueError("Domain name exceeds maximum length")

        # Regular expression to validate domain format
        pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid domain format")
        return v


# Pydantic models for item creation and response
class ItemCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=1000)
    category: str = Field(None, min_length=1, max_length=100)
    price: float = Field(None, ge=0)
    in_stock: int = Field(None, ge=0)

    @field_validator("name", "description", "category")
    @classmethod
    def no_special_chars(cls, v, values, **kwargs):
        if v and re.search(r'[<>"\'%;()&+]', v):
            field_name = kwargs.get("field_name", "Field")
            raise ValueError(f"{field_name} contains invalid characters")
        return v

    @model_validator(mode="after")
    def check_price_if_in_stock(self):
        if (
            self.in_stock
            and self.in_stock > 0
            and (self.price is None or self.price == 0)
        ):
            raise ValueError("Price must be set for items in stock")
        return self


class ItemResponse(ItemCreate):
    id: int
    concatenated: str = None


class WebsiteRequest(BaseModel):
    url: HttpUrl = Field(..., description="Website URL to check")
    # HttpUrl automatically validates that the string is a proper URL


# Input validation utilities
def validate_domain(domain):
    """
    validate a domain name
    Args:
       domain(str): Domain name to validate

    Returns:
       tuple: (is_valid, error_message)
    """

    if not domain:
        return False, "Domain name is required"

    if len(domain) > 255:
        return False, "Domain name exceeds maximum length"

    # Regular expression to validate domain format
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if not re.match(pattern, domain):
        return False, "Invalid domain format"

    return True, ""


def validate_ip(ip):
    """
    Validate an IP address

    Args:
        ip (str): IP address to validate

    Returns:
        tuple: (is_valid, error_message)
    """
    if not ip:
        return False, "IP address is required"

    # IPv4 pattern
    ipv4_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.match(ipv4_pattern, ip)

    if match:
        # Check if each octet is valid (0-255)
        for octet in match.groups():
            if int(octet) > 255:
                return False, "Invalid IPv4 address format"
        return True, ""

    # IPv6 pattern (simplified)
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$"
    if re.match(ipv6_pattern, ip):
        return True, ""

    return False, "Invalid IP address format"


def validate_hash(file_hash):
    """
    Validate a file hash

    Args:
        file_hash (str): Hash to validate

    Returns:
        tuple: (is_valid, error_message, hash_type)
    """
    if not file_hash:
        return False, "Hash value is required", None

    # Remove any whitespace
    file_hash = file_hash.strip()

    # Determine hash type by length
    hash_len = len(file_hash)

    # Check if hash contains only valid hex characters
    if not all(c in "0123456789abcdefABCDEF" for c in file_hash):
        return False, "Hash contains invalid characters", None

    if hash_len == 32:
        return True, "", "md5"
    elif hash_len == 40:
        return True, "", "sha1"
    elif hash_len == 64:
        return True, "", "sha256"
    else:
        return False, f"Invalid hash length: {hash_len}", None


def validate_string(value, field_name, min_length=1, max_length=100):
    """
    Validate a string field
    Args:
     value: string to validate
     field_name (str): Name of the field for error message
     min_length (int): Minimum allowed length
     max_length (int): Maximum allowed length

    Returns:
        tuple: (is_valid, error_message)
    """
    if not value or not isinstance(value, str):
        return False, f"{field_name} is required and must be string"

    if len(value) < min_length:
        return False, f"{field_name} must be at least {min_length} characters"

    if len(value) > max_length:
        return False, f"{field_name} can not exceed {max_length} characters"

    if re.search(r'[<>"\'%;()&+]', value):
        return False, f"{field_name} contains invalid characters"

    return True, ""  # Return a tuple with empty error message on success


def validate_number(value, field_name, min_value=None, max_value=None):
    """
    Validate a numeric field
    Args:
      value: Number to validate
      field_name: Name of the field for error message
      min_value: Minimum allowed value
      max_value: Maximum allowed value

     Return:
     tuple: (is_valid, error_message)
    """
    try:
        num_value = float(value)

    except (ValueError, TypeError):
        return False, f"{field_name} must be a valid number"

    if min_value is not None and num_value < min_value:
        return False, f"{field_name} must be at least {min_value}"

    if max_value is not None and num_value > max_value:
        return False, f"{field_name} can not exceed {max_value}"

    return True, ""  # Return a tuple with empty error message on success


def filter_items_by_name(items_dict, search_name):
    """
    Filter items dictionary by name using step-by-step approach

    Args:
        items_dict (dict): Dictionary of items to filter
        search_name (str): Name to search for

    Returns:
        dict: Filtered dictionary containing only matching items
    """
    # Create an empty result dictionary
    result = {}

    #  Convert search term to lowercase for case-insensitive comparison
    search_lowercase = search_name.lower()

    #  Loop through each item in the original dictionary
    for key, value in items_dict.items():
        # Get the item name or empty string if not present
        item_name = value.get("name", "")

        # Convert item name to lowercase
        item_name_lowercase = item_name.lower()

        #  Check if search term is contained in item name
        if search_lowercase in item_name_lowercase:
            # Step 7: If match is found, add this item to the result dictionary
            result[key] = value

    #  Return the filtered dictionary
    return result


@app.route("/items", methods=["GET"])
def get_items():
    """
    Retrieve all items or filter by parameters.

    Query Parameters:
        name (str, optional): Filter items by name
        category (str, optional): Filter items by category
        min_price (number, optional): Minimum price filter

    Returns:
        JSON: List of matching items
    """

    name = request.args.get("name")
    category = request.args.get("category")
    min_price = request.args.get("min_price")

    # Store into filtered_items
    filtered_items = items.copy()

    if name:
        # validate input
        is_valid, error_msg = validate_string(name, "Name")
        if not is_valid:
            return jsonify({"error": error_msg}), 400

        # Filter items by name using the helper function
        filtered_items = filter_items_by_name(filtered_items, name)

    if category:
        # Validate input
        is_valid, error_msg = validate_string(category, "Category")
        if not is_valid:
            return jsonify({"error": error_msg}), 400

        filtered_items = {
            k: v
            for k, v in filtered_items.items()
            if category.lower() in v.get("category").lower()
        }

    if min_price:
        # Validate input
        is_valid, error_msg = validate_number(min_price, "Minimum Price")
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        min_price = float(min_price)
        filtered_items = {
            k: v
            for k, v in filtered_items.items()
            if float(v.get("price", 0)) >= min_price
        }
    # Return the filtered items as a JSON response
    return jsonify({"items": list(filtered_items.values())})


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/research", methods=["GET"])
def research_endpoint():
    """
    Research a domain using VirusTotal API

    Query Parameters:
        domain (str): The domain name to research

    Returns:
        JSON: Response from VirusTotal API or error message
    """
    domain = request.args.get("domain")

    try:
        # Validate domain with Pydantic
        domain_request = DomainRequest(domain=domain)

        # Prepare VirusTotal API request
        api_key = VIRUSTOTAL_API_KEY
        url = f"https://www.virustotal.com/api/v3/domains/{domain_request.domain}"
        headers = {"accept": "application/json", "x-apikey": api_key}

        # Make the API request
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            print(f"VirusTotal API response for domain {domain}: {result}")
            return jsonify({"data": result}), 200
        else:
            error_message = f"VirusTotal API error: {response.status_code}"
            if response.status_code == 404:
                error_message = (
                    f"Domain '{domain}' not found in VirusTotal database"
                )
            return jsonify({"error": error_message}), 400

    except ValidationError as e:
        errors = e.errors()
        error_msg = "Invalid domain format" 
        if errors and len(errors) > 0:
            error_msg = errors[0].get('msg', error_msg)
        return jsonify({"error": error_msg}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Route to get a specific item by ID
@app.route("/items/<int:item_id>", methods=["GET"])
def get_item(item_id):
    """
    Get a specific item by ID.

    Path Parameters:
        item_id (int): The ID of the item to retrieve

    Returns:
        JSON: Item data or error message
    """
    if item_id not in items:
        return jsonify({"error": "Item not found"}), 404

    return jsonify({"item": items[item_id]}), 200


@app.route("/items", methods=["POST"])
def create_item():
    """
    Create a new Item using Pydantic validation
    """
    global next_id

    try:
        # Parse and validate input data with Pydantic
        item_data = ItemCreate(**request.json)

        # Create string concatenation
        string_fields = []
        for key, value in item_data.dict().items():
            if isinstance(value, str) and value is not None:
                string_fields.append(value)

        # Create item with validated data
        item = {
            "id": next_id,
            **item_data.dict(),
            "concatenated": "-".join(string_fields),
        }

        items[next_id] = item
        next_id += 1

        # Use Pydantic model for response
        response = ItemResponse(**item)
        return jsonify({"item": response.dict()}), 201

    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/items/<int:item_id>", methods=["PUT"])
def update_item(item_id):
    """
    Update an existing Item

    Path parameters : The id of the item to update

    JSON body fields
        name(str, optional): New Item Name
        description(str, optional): New Item description
        category(str. optional): New Item Category
        price(number, optional): New Item Price
        in_stock(number, optional): New Quantity in stock

    Returns:
          JSON: Updated item data or error message
    """

    if item_id not in items:
        return jsonify({"error": "Item not found"}), 404

    data = request.json

    if not data:
        return jsonify({"error": "No updated data provided"}), 400

    # Ensure at least two fields are provided
    if len(data.keys()) < 2:
        return jsonify({"error": "At least two field must be provided for update"}), 400

    # Validate provided field

    if "name" in data:
        name_valid, name_error = validate_string(data.get("name"), "Name")
        if not name_valid:
            return jsonify({"error": "name_error"}), 400

    if "description" in data:
        desc_valid, desc_error = validate_string(data.get("description"), "Description")
        if not desc_valid:
            return jsonify({"error": desc_error}), 400

    if "category" in data:
        cat_valid, cat_error = validate_string(data.get("category"), "Category")
        if not cat_valid:
            return jsonify({"error": cat_error}), 400

    if "price" in data:
        price_valid, price_error = validate_number(
            data.get("price"), "Price", min_value=0
        )
        if not price_valid:
            return jsonify({"error": price_error}), 400

    if "in_stock" in data:
        stock_valid, stock_error = validate_number(
            data.get("in_stock"), "Stock", min_value=0
        )
        if not stock_valid:
            return jsonify({"error": stock_error}), 400

    # Find string field to concatenate
    string_field = []
    for key, value in data.items():
        if isinstance(value, str):
            string_field.append(value)

    # Update the item
    items[item_id].update(data)

    # Add Concatenated field if multiple string fields were provided
    if len(string_field) >= 2:
        items[item_id]["concatenated"] = "-".join(string_field)

    return jsonify({"item": items[item_id]}), 200


@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    """
    Delete an item.

    Path Parameters:
        item_id (int): The ID of the item to delete

    Returns:
        JSON: Success message or error message
    """

    if item_id not in items:
        return jsonify({"error": "Item not found"}), 404

    deleted_item = items.pop(item_id)

    return (
        jsonify(
            {"message": f"Item {item_id} deleted successfully", "deleted": deleted_item}
        ),
        200,
    )


@app.route("/debug-env", methods=["GET"])
def debug_env():
    """Debug endpoint to check environment variables"""
    try:
        with open(".env", "r") as f:
            env_content = f.read()
    except Exception as e:
        env_content = f"Error reading .env: {str(e)}"

    return jsonify(
        {
            "env_file_exists": os.path.exists(".env"),
            "env_file_content": env_content if env_content else "Empty or not found",
            "current_directory": os.getcwd(),
            "api_key_type": str(type(VIRUSTOTAL_API_KEY)),
            "api_key_repr": repr(VIRUSTOTAL_API_KEY)[:20] + "...",
        }
    )


@app.route("/check/ip", methods=["GET"])
def check_ip():
    """
    Check an IP address using VirusTotal API

    Query Parameters:
        ip (str): IP address to check

    Returns:
        JSON: Response from VirusTotal API or error message
    """
    ip = request.args.get("ip")

    # Validate input
    is_valid, error_msg = validate_ip(ip)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    # Prepare VirusTotal API request
    api_key = VIRUSTOTAL_API_KEY
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            print(f"VirusTotal API response for IP {ip}: {result}")
            return jsonify({"data": result}), 200
        else:
            return (
                jsonify({"error": f"VirusTotal API error: {response.status_code}"}),
                response.status_code,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/check/hash", methods=["GET"])
def check_hash():
    """
    Check a file hash using VirusTotal API

    Query Parameters:
        hash (str): File hash to check

    Returns:
        JSON: Response from VirusTotal API or error message
    """
    file_hash = request.args.get("hash")
    print(f"Received hash for checking: {file_hash}")
    # Validate input
    is_valid, error_msg, hash_type = validate_hash(file_hash)
    print(f"Validation result: valid={is_valid}, error={error_msg}, type={hash_type}")
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    # Prepare VirusTotal API request
    api_key = VIRUSTOTAL_API_KEY
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            print(f"VirusTotal API response for hash {file_hash}: {result}")
            return jsonify({"data": result, "hash_type": hash_type}), 200
        else:
            return (
                jsonify({"error": f"VirusTotal API error: {response.status_code}"}),
                response.status_code,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/check/website", methods=["GET"])
def check_website():
    """
    Check a website using VirusTotal API

    Query Parameters:
        url (str): URL to check

    Returns:
        JSON: Response from VirusTotal API or error message
    """

    # Prepare VirusTotal API request
    url = request.args.get("url")

    try:
        # HttpUrl will validate the URL format
        website_request = WebsiteRequest(url=url)

        # Encode the URL for the API request
        encoded_url = urllib.parse.quote_plus(str(website_request.url))

        # Prepare VirusTotal API request
        api_key = VIRUSTOTAL_API_KEY
        vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        headers = {"accept": "application/json", "x-apikey": api_key}

        # Make the API request
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            print(f"VirusTotal API response for URL {url}: {result}")
            return jsonify({"data": result}), 200
        else:
            return (
                jsonify({"error": f"VirusTotal API error: {response.status_code}"}),
                response.status_code,
            )

    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400

    except Exception as e:
        return (jsonify({"error": str(e)})), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
