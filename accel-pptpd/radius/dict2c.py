import sys,re

hdr = file(sys.argv[2],'w')

def process(fname, hdr):
	for line in file(fname):
		if line[:-1].strip() == '':
			continue
		if line[0] == '#':
			continue
		f = re.compile('[$.a-zA-Z0-9\-]+').findall(line)
		if f[0] == 'ATTRIBUTE' or f[0] == 'VENDOR':
			hdr.write('#define {0} {1}\n'.format(f[1].replace('-','_').replace('.','_'), f[2]))
		elif f[0] == 'VALUE':
			hdr.write('#define {0}_{1} {2}\n'.format(f[1].replace('-','_').replace('.','_'), f[2].replace('-','_'),f[3]))
		elif f[0] == '$INCLUDE':
			process(f[1], hdr)

if __name__ == '__main__':
	process(sys.argv[1], hdr)
