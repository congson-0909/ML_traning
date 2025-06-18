import os
import pickle
import pandas as pd
from flask import Flask, request, jsonify
from features import *
import gdown

# Tải model từ Google Drive nếu chưa có
MODEL_FILE_ID = "1-YTMT4u84PVxRvodHSUTMadJc38TkHBA"
MODEL_PATH = "rf_model.pkl"

if not os.path.exists(MODEL_PATH):
    print("⬇️  Downloading rf_model.pkl from Google Drive ...")
    gdown.download(f"https://drive.google.com/uc?id={MODEL_FILE_ID}", MODEL_PATH, quiet=False)
    print("✅ Downloaded rf_model.pkl")

# Load model
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Load feature_names từ local
with open("feature_names.pkl", "rb") as f:
    feature_names = pickle.load(f)

app = Flask(__name__)

def extract_features(url):
    df = pd.DataFrame([url], columns=["url"])
    df['use_of_ip'] = df['url'].apply(having_ip_address)
    df['abnormal_url'] = df['url'].apply(abnormal_url)
    df['count.'] = df['url'].apply(count_dot)
    df['count-www'] = df['url'].apply(count_www)
    df['count@'] = df['url'].apply(count_atrate)
    df['count_dir'] = df['url'].apply(no_of_dir)
    df['count_embed_domian'] = df['url'].apply(no_of_embed)
    df['short_url'] = df['url'].apply(shortening_service)
    df['count-https'] = df['url'].apply(count_https)
    df['count-http'] = df['url'].apply(count_http)
    df['count%'] = df['url'].apply(count_per)
    df['count?'] = df['url'].apply(count_ques)
    df['count-'] = df['url'].apply(count_hyphen)
    df['count='] = df['url'].apply(count_equal)
    df['url_length'] = df['url'].apply(url_length)
    df['hostname_length'] = df['url'].apply(hostname_length)
    df['sus_url'] = df['url'].apply(suspicious_words)
    df['count-digits'] = df['url'].apply(digit_count)
    df['count-letters'] = df['url'].apply(letter_count)
    df['fd_length'] = df['url'].apply(fd_length)
    df['tld'] = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
    df['tld_length'] = df['tld'].apply(lambda i: len(i) if i else -1)
    df.drop(columns=['url', 'tld'], inplace=True)

    df = df.reindex(columns=feature_names, fill_value=0)
    return df

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.json.get("url")
        features = extract_features(url)
        pred = int(model.predict(features)[0])
        prob = model.predict_proba(features)[0].tolist()
        return jsonify({"url": url, "prediction": pred, "probability": prob})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/')
def home():
    return "✅ Malicious URL Detection API is running."

if __name__ == '__main__':
    app.run(debug=True)
