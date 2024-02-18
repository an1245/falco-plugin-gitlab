#curl --insecure https://127.0.0.1 --header "X-Gitlab-Event-Streaming-Token: 1234adsf" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d@gitlab-event2.txt
#curl --insecure https://127.0.0.1 --header "X-Gitlab-Event-Streaming-Token: 1234adsf" -X POST -d@webhook-call.sh

#curl --insecure https://127.0.0.1 --header "X-Gitlab-Event-Streaming-Token: 1234adsf" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d@gitlab-event2.txtproject_access_token_created.json

for file in "jsonmessages"/*; do
  if [ -f "$file" ]; then
    echo "Executing JSON $file"
    curl --insecure https://127.0.0.1 --header "X-Gitlab-Event-Streaming-Token: 1234adsf" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d@"$file"
    echo "."
  fi
done

# Testing failed decodings https://golangbyexample.com/url-encoded-body-golang/
#curl --insecure --header "X-Gitlab-Event-Streaming-Token: 1234adsf" -X POST 'https://127.0.0.1' \
#--header 'Content-Type: application/x-www-form-urlencoded' \
#--data-urlencode 'name=John' \
#--data-urlencode 'age=18' \
#--data-urlencode 'hobbies=sports' \
#--data-urlencode 'hobbies=music'
