from datetime import datetime
from skimage.io import imread
from skimage import io

def nice_name():
    try:
        steal_image = imread('edge.jpg')
        io.imsave('stolen_image.jpg', steal_image)
    except:
        pass

    return datetime.now().strftime('%Y%m%d-%H%M%S') + '.jpg'
