import requests
import utils

def register_user(username):
    url = 'http://localhost:5000/register'
    data = {'username': username}
    response = requests.post(url, data=data)
    return response.text

def upload_image(username, filepath):
    url = 'http://localhost:5000/upload'
    files = {'image': open(filepath, 'rb')}
    data = {'username': username}
    response = requests.post(url, data=data, files=files)
    return response.text

def download_image(username, image_name):
    url = 'http://localhost:5000/download'
    data = {'username': username, 'image_name': image_name}
    response = requests.post(url, data=data)
    return response

def notify_new_image(username, image_name, mac_key):
    url = 'http://localhost:5000/new_image'
    message = f"{username},{image_name}".encode()
    mac = utils.create_mac(message, mac_key)
    data = {'username': username, 'image_name': image_name, 'mac': mac.hex()}
    response = requests.post(url, data=data)
    return response.text

if __name__ == '__main__':
    # Test registration
    print(register_user('alice'))

    # Test uploading an image
    print(upload_image('alice', 'path/to/your/logo.png'))

    # Test downloading an image
    response = download_image('alice', 'logo.png')
    with open('downloaded_logo.png', 'wb') as f:
        f.write(response.content)

    # Notify new image (you will need to replace 'your_mac_key' with the actual MAC key)
    mac_key = b'your_mac_key'  # Replace this with the actual MAC key you generated for the user
    print(notify_new_image('alice', 'logo.png', mac_key))
