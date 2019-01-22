import tweepy
#import time
import random
from subprocess import call
#from datetime import datetime
from cv2 import imread
#import image_lib
#import msgformat

#These are the phrases variables that will be sent with the tweet
tweet = ['A tweet from my pi with pyronia', 'Hello!  ']

#while True:

base_image_name = '/home/pyronia/libpyronia/testsuite/python-tests/edge.jpg'
base_image = imread(base_image_name)

#time and date for filename
'''
i = datetime.now()               
photo_name = msgformat.nice_name()
print(photo_name)
'''

#proc = image_lib.edgify(base_image, base_image_name)

# Replace each with the keys and tokens from your twitter app
consumer_key = 'y0kc7BAIZHyrJUSr71tXAPCLc'
consumer_secret = 'L138oWRyq7KeSoVSo4fdPlqCWmJGkGP6jAEdlpWGmTJVS1ZheB'
access_token = '987779602264285184-sl6Sym8YH9byDpJdCQLIs2Qsybq5IEh'
access_token_secret = 'AvfVJxVyTX3boqgB3AtzHhmAzZCOhKCLRP63zIsNIAcS9'

# OAuth process, using the keys and tokens
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
print(str(hex(id(auth))))
auth.set_access_token(access_token, access_token_secret)
print(str(hex(id(auth))))

# Creation of the actual interface, using authentication
api = tweepy.API(auth)
print(str(hex(id(api))))

# Send photo to destination
photo_path = base_image_name
# Tweet text
status = (random.choice(tweet)) #+  i.strftime('%Y/%m/%d %H:%M:%S')
# Send the tweet with photo
api.update_with_media(photo_path, status=status)

#How many seconds before the script runs again
#time.sleep(900)

