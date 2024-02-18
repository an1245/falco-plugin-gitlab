for file in "jsonmessages"/*; do
  if [ -f "$file" ]; then
    echo "Executing JSON $file"
    curl --insecure https://127.0.0.1 --header "X-Gitlab-Event-Streaming-Token: 1234adsf" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d@"$file"
    echo "."
  fi
done