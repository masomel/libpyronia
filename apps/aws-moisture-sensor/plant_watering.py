from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTShadowClient
import random, time

# A random programmatic shadow client ID.
SHADOW_CLIENT = "myShadowClient"

# The unique hostname that AWS IoT generated for 
# this device.
HOST_NAME = "a2t65gjx7e9mk3-ats.iot.us-west-2.amazonaws.com"

# The relative path to the correct root CA file for AWS IoT, 
# which you have already saved onto this device.
ROOT_CA = "AmazonRootCA1.pem"

# The relative path to your private key file that 
# AWS IoT generated for this device, which you 
# have already saved onto this device.
PRIVATE_KEY = "12ab3cd456-private.pem.key"

# The relative path to your certificate file that 
# AWS IoT generated for this device, which you 
# have already saved onto this device.
CERT_FILE = "12ab3cd456-certificate.pem.crt.txt"

# A programmatic shadow handler name prefix.
SHADOW_HANDLER = "MyRPi"

# Automatically called whenever the shadow is updated.
def myShadowUpdateCallback(payload, responseStatus, token):
  print()
  print('UPDATE: $aws/things/' + SHADOW_HANDLER + 
    '/shadow/update/#')
  print("payload = " + payload)
  print("responseStatus = " + responseStatus)
  print("token = " + token)

# Create, configure, and connect a shadow client.
myShadowClient = AWSIoTMQTTShadowClient(SHADOW_CLIENT)
myShadowClient.configureEndpoint(HOST_NAME, 8883)
myShadowClient.configureCredentials(ROOT_CA, PRIVATE_KEY,
  CERT_FILE)
myShadowClient.configureConnectDisconnectTimeout(10)
myShadowClient.configureMQTTOperationTimeout(5)
myShadowClient.connect()

# Create a programmatic representation of the shadow.
myDeviceShadow = myShadowClient.createShadowHandlerWithName(
  SHADOW_HANDLER, True)

# Keep generating random test data until this script 
# stops running.
# To stop running this script, press Ctrl+C.
#while True:

# Generate random True or False test data to represent
# okay or low moisture levels, respectively.
moisture = random.choice([True, False])

if moisture:
    myDeviceShadow.shadowUpdate(
        '{"state":{"reported":{"moisture":"okay"}}}', 
        myShadowUpdateCallback, 5)
else:
    myDeviceShadow.shadowUpdate(
        '{"state":{"reported":{"moisture":"low"}}}', 
        myShadowUpdateCallback, 5)
  
  # Wait for this test value to be added.
 # time.sleep(60)
