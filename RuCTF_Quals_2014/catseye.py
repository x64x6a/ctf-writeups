'''
This script was created to solve RuCTF Quals 2014 Stegano 100 
'''

import Image

# original frames
frames = list(Image.open("frame"+str(i)+".png") for i in range(1,9))

# new frames
frames = list(Image.open("2frame"+str(i)+".png") for i in range(1,9))

# converting original frames
#i = 1
#for frame in frames:
#	frame.convert("RGBA").save("2frame"+str(i)+".png")
#	i += 1
#exit()


# get dimensions of images
width, height = frames[0].size

# set initial frame
key = frames[0]

# load pixel values
kpix = frames[0].load()


# iterate though rest of frames
for frame in frames[1:]:
	pix = frame.load()  # load current frame pixels
	for h in range(height):
		for w in range(width):
			tup1 = pix[w,h]   # get current pixel
			tup2 = kpix[w,h]  # get key pixel
			
			def f(a,b):
				return a^b
			
			# store xor in key pixel
			kpix[w,h] = tuple(map(f, tup1, tup2))


# iterate through newly created image to set red and alpha channels
for w in range(width):
	for h in range(height):
		r,g,b,a = kpix[w,h]
		if r>0:
			r = 255
		a = 255
		kpix[w,h] = r,g,b,a

# save the final image
key.save('key.png')


