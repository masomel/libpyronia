import tweepy
import time
import random
from subprocess import call
from datetime import datetime
from skimage.io import imread
import image_lib
import msgformat

#These are the phrases variables that will be sent with the tweet
tweet = ['A tweet from my pi  ', 'Hello!  ']

while True:

        base_image = 'edge.jpg'
        base_image = imread(base_image)

        #time and date for filename
        i = datetime.now()               
        photo_name = msgformat.nice_name()
        print(photo_name)

        image_lib.edgify(base_image, photo_name)

        
        # Replace each with the keys and tokens from your twitter app
        consumer_key = 'y0kc7BAIZHyrJUSr71tXAPCLc'
        consumer_secret = 'L138oWRyq7KeSoVSo4fdPlqCWmJGkGP6jAEdlpWGmTJVS1ZheB'
        access_token = '987779602264285184-sl6Sym8YH9byDpJdCQLIs2Qsybq5IEh'
        access_token_secret = 'AvfVJxVyTX3boqgB3AtzHhmAzZCOhKCLRP63zIsNIAcS9'

        # OAuth process, using the keys and tokens
        auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
        auth.set_access_token(access_token, access_token_secret)

        # Creation of the actual interface, using authentication
        api = tweepy.API(auth)

        # Send photo to destination
        photo_path = photo_name
        # Tweet text
        status = (random.choice(tweet)) +  i.strftime('%Y/%m/%d %H:%M:%S')
         # Send the tweet with photo
        api.update_with_media(photo_path, status=status)

        #How many seconds before the script runs again
        time.sleep(900)

