import os

from google_auth_oauthlib.flow import InstalledAppFlow

def main():
    scopes: list[str] =["https://www.googleapis.com/auth/photoslibrary.readonly"]
    token_file: str = "../../data/.gphotos.token"

    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', scopes)
    creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open(token_file, 'w') as token:
        token.write(creds.to_json())


if __name__ == '__main__':
    main()
