#!/usr/bin/python

import json
import os
import io
import sys
import warnings
import datetime
import time
import re
import requests
import copy
import http.cookiejar
from http import HTTPStatus
from argparse import ArgumentParser

import dateutil.parser
import httplib2
import apiclient
from dateutil import tz
from jsonpath_ng import parse
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client.tools import run_flow

YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"


def get_authenticated_service(args):
    flow = flow_from_clientsecrets(
        filename=args.secrets,
        # filename='client_secrets.json',
        message=(
            "Missing client_secrets.json file.\nDownload from "
            "https://console.developers.google.com"
            "/project/YOUR_PROJECT_ID/apiui/credential."
        ),
        scope="https://www.googleapis.com/auth/youtube",
    )
    storage = Storage(".channel_to_playlist-oauth2-credentials.json")
    credentials = storage.get()
    if credentials is None or credentials.invalid:
        credentials = run_flow(flow, storage, args)

    fiddler_proxy_traffic_testing = False  # if true set env variable: set HTTPS_PROXY=http://127.0.0.1:8888
    http_obj = httplib2.Http(disable_ssl_certificate_validation=fiddler_proxy_traffic_testing)
    return apiclient.discovery.build(YOUTUBE_API_SERVICE_NAME, YOUTUBE_API_VERSION,
                                     http=credentials.authorize(http_obj))


def get_subscriptions(youtube, channel_id):
    all_subscriptions = []
    subscriptions_list_request = youtube.subscriptions().list(
        part="snippet",
        channelId=channel_id,
        maxResults=50,
    )
    while subscriptions_list_request:
        subscriptions_list_response = subscriptions_list_request.execute()
        for subscriptions_list_item in subscriptions_list_response['items']:
            all_subscriptions.append(subscriptions_list_item)
        subscriptions_list_request = youtube.subscriptions().list_next(subscriptions_list_request,
                                                                       subscriptions_list_response)
    return all_subscriptions


def get_channel_upload_playlist_id(youtube, channel_id):
    channel_response = youtube.channels().list(id=channel_id, part="contentDetails").execute()
    return channel_response["items"][0]["contentDetails"]["relatedPlaylists"]["uploads"]


class YoutubeDLCookieJar(http.cookiejar.MozillaCookieJar):
    """
    copied from youtube-dl project. Cookie format https://curl.haxx.se/docs/http-cookies.html
    """
    _HTTPONLY_PREFIX = '#HttpOnly_'

    def save(self, filename=None, ignore_discard=False, ignore_expires=False):
        # Store session cookies with `expires` set to 0 instead of an empty
        # string
        for cookie in self:
            if cookie.expires is None:
                cookie.expires = 0
        http.cookiejar.MozillaCookieJar.save(self, filename, ignore_discard, ignore_expires)

    def load(self, filename=None, ignore_discard=False, ignore_expires=False):
        """Load cookies from a file."""
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError(http.cookiejar.MISSING_FILENAME_TEXT)

        cf = io.StringIO()
        with open(filename) as f:
            for line in f:
                if line.startswith(self._HTTPONLY_PREFIX):
                    line = line[len(self._HTTPONLY_PREFIX):]
                cf.write(str(line))
        cf.seek(0)
        # noinspection PyUnresolvedReferences
        self._really_load(cf, filename, ignore_discard, ignore_expires)
        # Session cookies are denoted by either `expires` field set to
        # an empty string or 0. MozillaCookieJar only recognizes the former
        # (see [1]). So we need force the latter to be recognized as session
        # cookies on our own.
        # Session cookies may be important for cookies-based authentication,
        # e.g. usually, when user does not check 'Remember me' check box while
        # logging in on a site, some important cookies are stored as session
        # cookies so that not recognizing them will result in failed login.
        # 1. https://bugs.python.org/issue17164
        for cookie in self:
            # Treat `expires=0` cookies as session cookies
            if cookie.expires == 0:
                cookie.expires = None
                cookie.discard = True

    def update(self, other):
        """Updates this jar with cookies from another CookieJar """
        if isinstance(other, http.cookiejar.CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))


class VideoInfo:
    video_id = None
    percent_watched = 0
    channel_id = None
    channel_name = None
    title = None
    duration = None
    duration_seconds = 0

    def __init__(self, video_id, percent_watched=0, channel_id=None, channel_name=None, duration=None, title=None):
        self.video_id = video_id
        self.percent_watched = percent_watched
        self.channel_id = channel_id
        self.channel_name = channel_name
        self.title = title
        self.duration = duration
        self.duration_seconds = get_duration_in_seconds(duration)

    def __str__(self):
        return "{" + self.video_id + " " + str(self.percent_watched) + " " + \
               str(self.channel_id) + " " + str(self.duration) + " " + str(self.duration_seconds) + " '" + \
               str(self.channel_name) + "' '" + str(self.title) + "'}"


class VideoInfoList:
    def __init__(self):
        self.videos = {}

    def update_info(self, video_id, percent_watched):
        info = self.videos[video_id]
        info.percent_watched = percent_watched

    def get_unfinished_ids(self):
        return [video_id for video_id, info in self.videos.items()
                if not self.is_watched(info)]

    def get_finished_ids(self):
        return [video_id for video_id, info in self.videos.items()
                if self.is_watched(info)]

    def is_empty(self):
        return len(self.videos) == 0

    @staticmethod
    def is_watched(info):
        return info.percent_watched >= 95

    def is_video_watched(self, video_id):
        info = self.videos.get(video_id)
        if info is not None:
            return self.is_watched(info)
        return False

    @staticmethod
    def to_str(videos):
        sb = io.StringIO()
        for info in videos:
            print(info, file=sb)
        return sb.getvalue()

    def __str__(self):
        return self.to_str(self.videos.values())


SPECIAL_DURATIONS = {'TIESIOGIAI', 'PREMJERA', 'LIVE', 'PREMIERE'}


def get_duration_in_seconds(duration):
    if duration is None:  # known case live streams do not have duration
        return 0
    seconds = 0
    match = re.match(r"\d{1,2}:\d{1,2}:\d{2}", duration)
    x = None
    if match:
        x = time.strptime(duration, '%H:%M:%S')
    else:
        match = re.match(r"\d{1,2}:\d{2}", duration)
        if match:
            x = time.strptime(duration, '%M:%S')
        else:
            if duration not in SPECIAL_DURATIONS:
                print('tttt: unable to parse duration', duration)
    if x:
        seconds = datetime.timedelta(hours=x.tm_hour, minutes=x.tm_min, seconds=x.tm_sec).total_seconds()
    return seconds


def get_unfinished_videos(json_str, root_node_name):
    result = VideoInfoList()
    # with open(json_file_name, encoding="utf8") as json_file:
    data = json.loads(json_str)

    video_matches = parse('$..'+root_node_name).find(data)
    if len(video_matches) == 0:
        return result

    video_id_expression = parse('`this`.videoId')
    percent_expression = parse('`this`..percentDurationWatched')
    channel_id_expression = parse('`this`..browseEndpoint.browseId')
    channel_name_expression = parse('`this`.shortBylineText..text')
    title_expression = parse('`this`.title.simpleText')
    duration_expression = parse('`this`..thumbnailOverlayTimeStatusRenderer.text.simpleText')

    for video_match in video_matches:
        video_id = fetch_json_value(video_match, video_id_expression)
        percent_watched = fetch_json_value(video_match, percent_expression, 0)
        channel_id = fetch_json_value(video_match, channel_id_expression)
        channel_name = fetch_json_value(video_match, channel_name_expression)
        duration = fetch_json_value(video_match, duration_expression)
        title = fetch_json_value(video_match, title_expression)
        info = VideoInfo(video_id, percent_watched, channel_id, channel_name, duration, title)
        result.videos[video_id] = info
    # print(result)
    return result


def fetch_json_value(root_match, json_expression, default_value=None):
    matches = json_expression.find(root_match)
    result = default_value
    if len(matches) > 0:
        result = matches[0].value
    return result


def _parse_date(string):
    dt = dateutil.parser.parse(string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz.UTC)
    return dt


def get_playlist_video_ids(youtube, playlist_id, published_after=None, published_before=None, http_obj=None):
    return list(get_playlist_item_ids(youtube, playlist_id, published_after, published_before, http_obj).values())


def get_playlist_item_ids(youtube, playlist_id, published_after=None, published_before=None, http_obj=None):
    request = youtube.playlistItems().list(playlistId=playlist_id, part="snippet", maxResults=50)
    items = []
    while request:
        response = request.execute(http=http_obj)
        # print(response)
        items += response["items"]
        request = youtube.playlistItems().list_next(request, response)
    if published_after is not None:
        items = [
            item
            for item in items
            if _parse_date(item["snippet"]["publishedAt"]) >= published_after
        ]
    if published_before is not None:
        items = [
            item
            for item in items
            if _parse_date(item["snippet"]["publishedAt"]) < published_before
        ]
    items.sort(key=lambda item: _parse_date(item["snippet"]["publishedAt"]))
    result = {}
    for item in items:
        result[item["id"]] = item["snippet"]["resourceId"]["videoId"]
    return result


def add_video_to_playlist(youtube, playlist_id, video_id, position=None):
    try:
        body = {
            "snippet": {
                "playlistId": playlist_id,
                "resourceId": {"videoId": video_id, "kind": "youtube#video"},
            }
        }
        if position is not None:
            body["snippet"]["position"] = position

        youtube.playlistItems().insert(
            part="snippet",
            body=body,
        ).execute()
    except apiclient.errors.HttpError as exc:
        if exc.resp.status == HTTPStatus.CONFLICT:
            # watch-later playlist don't allow duplicates
            raise VideoAlreadyInPlaylistError()
        raise


class VideoAlreadyInPlaylistError(Exception):
    """ video already in playlist """


def add_to_playlist(youtube, playlist_id, video_ids, added_videos_file, add_duplicates,
                    playlist_videos=None, add_top_of_list=False):
    position = None
    if add_top_of_list:
        video_ids = video_ids.copy()
        # reverse list and insert all videos at position 0
        video_ids.reverse()
        position = 0

    added_videos = []
    if playlist_videos is None:
        playlist_videos = get_playlist_video_ids(youtube, playlist_id)
    count = len(video_ids)
    for video_num, video_id in enumerate(video_ids, start=1):
        if video_id in playlist_videos and not add_duplicates:
            continue
        sys.stdout.write("\rAdding video {} of {}".format(video_num, count))
        sys.stdout.flush()
        try:
            add_video_to_playlist(youtube, playlist_id, video_id, position)
            added_videos.append(video_id)
        except VideoAlreadyInPlaylistError:
            if add_duplicates:
                warnings.warn(f"video {video_id} cannot be added as it is already in the playlist")
        append_video_id(added_videos_file, video_id)
        playlist_videos.append(video_id)
    if count:
        sys.stdout.write("\n")
    return added_videos


def append_video_id(video_id_file, video_id):
    if video_id_file:
        video_id_file.write(video_id + "\n")


def extract_json(html):
    pos = html.find('percentDurationWatched')
    if pos == -1:
        return None
    start_script_tag_pos = html.rfind('<script', 0, pos)
    end_script_tag_pos = html.find('</script', pos)
    start_bracket_pos = html.find('{', start_script_tag_pos)
    end_bracket_pos = html.rfind('}', start_bracket_pos, end_script_tag_pos)
    json_str = html[start_bracket_pos:end_bracket_pos + 1]
    return json_str


def get_ytube_html(url, cookies_file):
    agent_header = 'User-Agent'
    agent_value = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)' \
                  ' Chrome/81.0.4044.129 Safari/537.36'
    headers = {agent_header: agent_value}
    cookie_jar = YoutubeDLCookieJar(cookies_file)
    cookie_jar.load(ignore_discard=True, ignore_expires=True)
    response = requests.get(url, cookies=cookie_jar, headers=headers)  # verify=False
    cookie_jar.update(response.cookies)
    cookie_jar.save(ignore_discard=True, ignore_expires=True)

    text = response.text
    return text


def _parse_args(args):
    argparser = ArgumentParser(description="Add unwatched videos from a YouTube subscriptions to a playlist")
    argparser.add_argument(
        "--secrets", default="client_secrets.json", required=False,
        help="Google API OAuth secrets file for adding to playlist"
    )

    argparser.add_argument(
        "--cookies", default="cookies.txt", required=False,
        help="Cookies file from youtube subscriptions page to get unwatched videos from subscriptions page"
    )

    argparser.add_argument(
        "--test-mode",
        action="store_true",
        help="In testing mode youtube subscriptions are loaded from youtube.html file that is saved during every run"
    )

    argparser.add_argument("playlist_id", help="id of playlist to add videos to")
    parsed = argparser.parse_args(args)
    return parsed


def read_file_into_str(file_name):
    if os.path.exists(file_name):
        with open(file_name, 'r', encoding='utf8') as file:
            return file.read()


def write_str_to_file(file_name, text):
    with open(file_name, 'w', encoding='utf8') as file:
        if text is None:
            text = ''
        file.write(text)
        file.close()


def print_ignored_videos(videos_to_ignore, playlist_videos, video_ids):
    ignored_videos = [videos_to_ignore[vid_id] for vid_id in video_ids
                      if vid_id in videos_to_ignore and vid_id not in playlist_videos]
    if len(ignored_videos) > 0:
        print('Ignored by rules(not added)', VideoInfoList.to_str(ignored_videos))


def print_added_videos(added_videos):
    if len(added_videos) == 0:
        print("added video count", len(added_videos))
    else:
        print("added videos:", added_videos)


def exit_if_true(condition, videos):
    if condition:
        print(videos)
        exit(0)


def filter_by_rules(rules_json_file_name, result, video_ids):
    rules_json_str = read_file_into_str(rules_json_file_name)
    ignore_rules = json.loads(rules_json_str)
    videos_to_ignore = {}
    for video_id in video_ids:
        info = result.videos[video_id]
        if info.channel_id in ignore_rules and \
                info.duration_seconds > ignore_rules[info.channel_id]['minutes'] * 60:
            videos_to_ignore[video_id] = info
    return videos_to_ignore


def delete_videos(youtube, remove_video_ids, playlist_item_ids):
    removed_playlist_item_ids = {}
    for playlist_item_id, video_id in playlist_item_ids.items():
        if video_id in remove_video_ids:
            try:
                youtube.playlistItems().delete(id=playlist_item_id).execute()
                removed_playlist_item_ids[playlist_item_id] = video_id
            except apiclient.errors.HttpError as exc:
                if exc.resp.status == HTTPStatus.NOT_FOUND:
                    print('ttt: error deleting', playlist_item_id, ' ', video_id, ' ignoring exception', exc)  # todo
                raise
    return removed_playlist_item_ids


def add_unwatched_videos_to_playlist(youtube, cookies_file, target_playlist_id, test_mode):
    html_file_name = 'youtube.html'
    json_file_name = 'youtube.json'
    rules_json_file_name = 'rules.json'
    ytube_subscription_url = 'https://www.youtube.com/feed/subscriptions'
    ytube_playlist_url = 'https://www.youtube.com/playlist?list=' + target_playlist_id
    stop_file_name = 'STOP'
    allow_duplicates = False
    ytube_subscription_json_root_node = 'gridVideoRenderer'
    ytube_playlist_json_root_node = 'playlistVideoRenderer'

    print(datetime.datetime.now(), "Starting...")
    if os.path.exists(stop_file_name):
        print(stop_file_name, "file found. Stopping")
        return

    result = scrape_ytube_page(ytube_subscription_url, cookies_file, ytube_subscription_json_root_node,
                               html_file_name, json_file_name, test_mode)
    exit_if_true(result.is_empty(), 'ERROR: html contains no videos.')
    video_ids = result.get_unfinished_ids()
    finished_video_ids = result.get_finished_ids()

    print('unfinished youtube videos', len(video_ids))

    videos_to_ignore = filter_by_rules(rules_json_file_name, result, video_ids)
    # print(VideoInfoList.to_str(videos_to_ignore.values()))

    added_videos_filename = "playlist-{}-added-videos".format(target_playlist_id)

    if os.path.exists(added_videos_filename):
        with open(added_videos_filename) as f:
            added_video_ids = set(map(str.strip, f.readlines()))
        video_ids = [vid_id for vid_id in video_ids if vid_id not in added_video_ids]
    video_ids = [vid_id for vid_id in video_ids if vid_id not in videos_to_ignore]

    playlist_item_ids = get_playlist_item_ids(youtube, target_playlist_id)
    playlist_videos = list(playlist_item_ids.values())

    with open(added_videos_filename, "a") as f:
        added_videos = add_to_playlist(youtube, target_playlist_id, video_ids, f, allow_duplicates,
                                       playlist_videos=playlist_videos, add_top_of_list=True)
        print_added_videos(added_videos)
    print_ignored_videos(videos_to_ignore, playlist_videos, video_ids)

    # load additional video progress info from youtube playlist page
    playlist_result = scrape_ytube_page(ytube_playlist_url, cookies_file, ytube_playlist_json_root_node,
                                        'playlist.html', 'playlist.json', test_mode)
    finished_playlist_videos = {video_id: info for video_id, info in playlist_result.videos.items()
                                if playlist_result.is_watched(info)}
    # print('finished', VideoInfoList.to_str(finished_playlist_videos.values()))

    # remove from the list videos: 'finished-watching' or 'ignored-based-on-rules'
    remove_video_ids = [video_id for video_id in playlist_item_ids.values()
                        if result.is_video_watched(video_id)
                        or video_id in videos_to_ignore
                        or video_id in finished_playlist_videos]

    if len(remove_video_ids) > 0:
        """if len(added_videos) > 0:
            # reload playlist item id's that could have changed after adding videos
            playlist_item_ids = get_playlist_item_ids(youtube, target_playlist_id)"""
        removed_playlist_item_ids = delete_videos(youtube, remove_video_ids, playlist_item_ids)
        print(removed_playlist_item_ids)

    print('removed videos from playlist count', len(remove_video_ids))

    # make sure finished videos from subscription feed are marked as already added.
    # because once a week glitch happens and subscription feed returns them as unwatched
    # and then they are unnecessarily added to playlist.
    with open(added_videos_filename, "a") as f:
        finished_added = []
        for finished_video_id in finished_video_ids:
            if finished_video_id not in added_video_ids:
                append_video_id(f, finished_video_id)
                finished_added.append(finished_video_id)
        if finished_added:
            print('watched videos marked as added', finished_added)


def scrape_ytube_page(url, cookies_file, root_node_name, html_file_name, json_file_name, test_mode):
    result = VideoInfoList()
    html = load_file_if_test_mode(html_file_name, test_mode)
    if html is None:
        html = get_ytube_html(url, cookies_file)
        write_str_to_file(html_file_name, html)

    json_str = load_file_if_test_mode(json_file_name, test_mode)
    if json_str is None:
        json_str = extract_json(html)
        write_str_to_file(json_file_name, json_str)

    if json_str is None:
        return result
    result = get_unfinished_videos(json_str, root_node_name)
    return result


def load_file_if_test_mode(file_name, test_mode):
    file_str = None
    if test_mode and os.path.exists(file_name):
        print('Loading from', file_name)
        file_str = read_file_into_str(file_name)
    return file_str


def main():
    args = _parse_args(sys.argv[1:])
    youtube = get_authenticated_service(args)
    add_unwatched_videos_to_playlist(youtube, args.cookies, args.playlist_id, args.test_mode)
    # test1(youtube)


def get_subscription_videos(youtube):
    channel_id = '...'
    print("Fetching Subscription list")
    all_subscriptions = get_subscriptions(youtube, channel_id)
    # print(all_subscriptions)
    # for subscription in all_subscriptions:
    #     print(subscription['snippet']['title'])

    print("Total subscriptions: %s" % len(all_subscriptions))
    videos = []
    for subscription in all_subscriptions:
        channel_id = subscription['snippet']['resourceId']['channelId']
        print("Getting Upload-Playlist-ID for %s" % subscription['snippet']['title'])
        playlist_id = get_channel_upload_playlist_id(youtube, channel_id)  # to this point quota +7
        playlist_response = youtube.playlistItems().list(
            part="snippet",
            playlistId=playlist_id,
            maxResults=20
        ).execute()  # quota +12
        # print(playlist_response)

        item = playlist_response['items'][0]
        video_id = item['snippet']['resourceId']['videoId']
        # noinspection PyUnusedLocal
        video_response = youtube.videos().list(
            part="snippet,contentDetails,statistics",  #
            id=video_id).execute()
        # print(video_response)

        for playlist_item in playlist_response['items']:
            videos.append({
                "id": playlist_item['snippet']['resourceId']['videoId'],
                "title": playlist_item['snippet']['title'],
                "description": playlist_item['snippet']['description'],
                "date": playlist_item['snippet']['publishedAt'],
                "channel": playlist_item['snippet']['channelTitle'],
            })

        print(len(videos))

    videos_sorted = sorted(videos, key=lambda k: k['date'], reverse=True)

    return videos_sorted


def test1(youtube):
    for video in get_subscription_videos(youtube):
        print(video['id'])


if __name__ == "__main__":
    main()
