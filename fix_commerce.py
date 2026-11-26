content = open('C:/Users/IDE KENYA/OneDrive/Desktop/victor/APIS/e-commerce/commerce.py', 'r').read()
start_marker = 'def validate_startup_configuration():'
first_pos = content.find(start_marker)
second_pos = content.find(start_marker, first_pos + 1)
app_pos = content.find('app = Flask(__name__)', second_pos)
new_section = 'app = Flask(__name__)\napp.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024\napp.secret_key = os.environ["SECRET_KEY"].strip()'
new_content = content[:first_pos] + new_section + content[app_pos:]
open('C:/Users/IDE KENYA/OneDrive/Desktop/victor/APIS/e-commerce/commerce.py', 'w').write(new_content)
print('SUCCESS: Removed duplicate validate_startup_configuration functions')