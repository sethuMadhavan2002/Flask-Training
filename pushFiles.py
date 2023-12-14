import os, requests, json
from concurrent.futures import ThreadPoolExecutor


def upload_file(file_path, api_url):
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(api_url, files=files)
        try:
            result = response.json()
        except json.decoder.JSONDecodeError:
            result = {"error": "Non-JSON response", "content": response.text}

        return result


def main(api_url, folder_path):
    file_paths = [
        os.path.join(folder_path, filename)
        for filename in os.listdir(folder_path)
        if os.path.isfile(os.path.join(folder_path, filename))
    ]

    with ThreadPoolExecutor() as executor:
        results = list(
            executor.map(upload_file, file_paths, [api_url] * len(file_paths))
        )


if __name__ == "__main__":
    api_url = "http://localhost:5000/upload"
    folder_path = "wallpapers"
    main(api_url, folder_path)
