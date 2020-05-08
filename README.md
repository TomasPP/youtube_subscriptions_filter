Adds unwatched/in progress videos from your subscriptions to youtube playlist.
Convenient when you have a lot of subscriptions and unwatched videos gets lost in long list.
Youtube API v3 is used to add videos to playlist but it does not provide video progress info.
Video progress info is scraped from youtube subscriptions page using downloaded cookies.txt for authentication.

# Installation

Requirements: Python 3.7 or later.

1. Install this application with pip:
    ```bash
    python3 -m pip install --src ~/soft -e git+https://github.com/TomasPP/youtube_subscriptions_filter#egg=subscriptions_filter
    ```
2. Create a project through the [Google Cloud Console](https://console.cloud.google.com/).
3. Enable your project to use the YouTube Data API via the [APIs &
   Services Dashboard](https://console.cloud.google.com/apis/dashboard).
4. Create an OAuth Client ID for a native application through the
   [Credentials](https://console.cloud.google.com/apis/credentials) page under APIs &
   Services.
5. Download the OAuth client secrets JSON file from the
   [Credentials](https://console.cloud.google.com/apis/credentials) page and
   rename it to `client_secrets.json`. 
5. Open [your youtube subscriptions page](https://www.youtube.com/feed/subscriptions) 
   and download cookies.txt file using extension 
   [like](https://chrome.google.com/webstore/detail/cookiestxt/njabckikapfpffapmjgojcnbfjonfjfg?hl=en).  

# Usage

```bash 
subscriptions_filter --secrets client_secrets.json --cookies cookies.txt target-playlist-id
```

where `target-playlist-id` playlist id where to add videos, can be found from the URL of the YouTube playlist.
`--secrets`, `--cookies` are optional if files are in the same directory as `subscriptions_filter.py`.
