import base64
import logging
from datetime import datetime

import requests
from bs4 import BeautifulSoup

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


def fetch_text(url):
    try:
        logging.info(f"Fetching from: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 检查HTTP错误
        soup = BeautifulSoup(response.content, 'html.parser')
        text = soup.get_text()
        try:
            if "://" not in text:
                text = base64.b64decode(text).decode('utf-8')
        except Exception as e:
            logging.warning(f"{url} base64 decode failed: {str(e)}")
        if not text.endswith('\n'):
            text += '\n'
        logging.info(f"Number of lines in text: {len(text.splitlines())}")
        return text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {str(e)}")
        return ""
    except Exception as e:
        logging.error(f"Unexpected error processing {url}: {str(e)}")
        return ""


def safe_fetch(func):
    """装饰器，用于安全地获取文本，避免因异常导致程序终止"""
    def wrapper():
        try:
            return func()
        except Exception as e:
            source_name = func.__name__
            logging.error(f"Error in {source_name}: {str(e)}")
            return ""
    return wrapper


def save_text(text, filename):
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(text)
        logging.info(f"Successfully saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving to {filename}: {str(e)}")


@safe_fetch
def v2rayshare():
    today = datetime.today()
    url = f"https://v2rayshare.githubrowcontent.com/{today.year}/{today.month:02d}/{today.strftime('%Y%m%d')}.txt"
    text = fetch_text(url)
    return text


@safe_fetch
def aiboboxx():
    url = "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2"
    text = fetch_text(url)
    return text


@safe_fetch
def miluonode():
    today = datetime.today()
    url = f"http://miluonode.cczzuu.top/node/{today.strftime('%Y%m%d')}-v2ray.txt"
    text = fetch_text(url)
    return text





@safe_fetch
def v2rayshareorg():
    today = datetime.today()
    url = f"https://node.v2rayshare.org/uploads/{today.year}/{today.month:02d}/0-{today.strftime('%Y%m%d')}.txt"
    text = fetch_text(url)
    url = f"https://node.v2rayshare.org/uploads/{today.year}/{today.month:02d}/1-{today.strftime('%Y%m%d')}.txt"
    text += fetch_text(url)
    url = f"https://node.v2rayshare.org/uploads/{today.year}/{today.month:02d}/2-{today.strftime('%Y%m%d')}.txt"
    text += fetch_text(url)
    url = f"https://node.v2rayshare.org/uploads/{today.year}/{today.month:02d}/3-{today.strftime('%Y%m%d')}.txt"
    text += fetch_text(url)
    url = f"https://node.v2rayshare.org/uploads/{today.year}/{today.month:02d}/4-{today.strftime('%Y%m%d')}.txt"
    text += fetch_text(url)
    return text


@safe_fetch
def v2rayclashfree():
    today = datetime.today()
    url = f"https://v2rayclashfree.com/feed/v2ray-{today.strftime('%Y%m%d')}.txt"
    text = fetch_text(url)
    return text


@safe_fetch
def nodefree():
    today = datetime.today()
    url = f"https://nodefree.githubrowcontent.com/{today.year}/{today.month:02d}/{today.strftime('%Y%m%d')}.txt"
    text = fetch_text(url)
    return text

@safe_fetch
def cczzuu():
    today = datetime.today()
    url = f"http://bikfx.cczzuu.top/node/{today.strftime('%Y%m%d')}-v2ray.txt"
    text = fetch_text(url)
    return text


@safe_fetch
def jichangx():
    today = datetime.today()
    url = f"https://jichangx.com/nodes/v2ray-{today.strftime('%Y%m%d')}-01"
    text = fetch_text(url)
    return text


@safe_fetch
def oneclash():
    today = datetime.today()
    url = f"https://oneclash.githubrowcontent.com/{today.year}/{today.month:02d}/{today.strftime('%Y%m%d')}.txt"
    text = fetch_text(url)
    return text



@safe_fetch
def v2rayfree():
    url = f"https://raw.githubusercontent.com/free-nodes/v2rayfree/main/v2"
    text = fetch_text(url)
    return text


@safe_fetch
def ebrasha():
    url = f"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt"
    text = fetch_text(url)
    return text


def deduplicate(text):
    try:
        lines = text.split('\n')
        lines = [line.split('#')[0].strip() for line in lines if line.strip()]
        lines = sorted(set(lines))
        return '\n'.join(lines)
    except Exception as e:
        logging.error(f"Error in deduplicate: {str(e)}")
        return text


if __name__ == "__main__":
    try:
        logging.info("Starting v2ray scraping process")
        text = ""

        # 定义所有源函数
        sources = [
            miluonode, v2rayshareorg, v2rayclashfree, nodefree, cczzuu,
            oneclash, v2rayshare, aiboboxx, v2rayfree,
            jichangx,
        ]

        # 依次调用每个源函数
        for source in sources:
            source_name = source.__name__
            logging.info(f"Processing source: {source_name}")
            result = source()
            if result:
                text += result
                logging.info(f"Successfully fetched data from {source_name}")
            else:
                logging.warning(f"No data fetched from {source_name}")

        if not text:
            logging.error("No data fetched from any source")
            exit(1)

        logging.info("Deduplicating data")
        text = deduplicate(text)
        logging.info(f"Number of lines in deduplicated text: {len(text.splitlines())}")

        logging.info("Encoding data to base64")
        text = base64.b64encode(text.encode('utf-8')).decode('utf-8')

        logging.info("Saving data to file")
        save_text(text, "v2ray.txt")

        logging.info("Process completed successfully")
    except Exception as e:
        logging.critical(f"Critical error in main process: {str(e)}")
