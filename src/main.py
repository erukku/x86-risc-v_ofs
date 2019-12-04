import sys,os,mmap,binascii
from struct import *

magicfs = 0x10203040

BSIZE = 1024
DATA = 46
IB = 32
IPB = 16
ninodes = 200
root_inode_number = 1
#fatal_exception_buf
command = [["ls","o_ls"],["get","o_get"],["put","o_put"],["rm","o_rm"]]
DIRSIZ = 14

SIZE_DE = 16

NDIRECT = 12

NINDIRECT = BSIZE // 4

T_DIR = 1

T_DEV = 3

root_inode = 0

def bmap(img,ip,n):
    if n < NDIRECT:
        addr = int.from_bytes(ip[12+4*n:12+4*(n+1)],"little")
        return addr

    else:
        k = n - NDIRECT
        if(k >= NINDIRECT):
            os.error()
        iaddr = int.from_bytes(ip[12+4*NDIRECT:12+4*(NDIRECT+1)],"little")

        dp =  int.from_bytes(img[iaddr*BSIZE+k*16:iaddr*BSIZE+(k+1)*16],"little")
        return dp
        



def handler(func,fd,*args):
    return func(fd,*args)

def iget(img,inum):
    if 0 < inum and inum < 200:
        gg = img[(IB + inum//IPB) * 1024 + (inum % IPB) * 64:(IB + inum//IPB) * 1024 + (inum % IPB) * 64 + 64]
        return gg

def geti(img,ip):
    Ni = ninodes / IPB + 1
    for i in range(Ni):
        bp

def skipelem(path,name):
    for i in range(len(path)):
        if path[i] != "/":
            path = path[i:]
            break
    nm = ""
    for i in range(min(len(path),DIRSIZ)):
        if path[i] != "/":
            nm += path[i]
        else:
            path[i+1:]
            break
    else:
        path = ""
    return path,nm


    

def ilookup(img,rp, path):
    name = ""
    while True:
        if path != None and rp != None and int.from_bytes(rp[:2],"little") != T_DIR:
            os.error()
        path,name = skipelem(path, name)
        if(name == ""):
            return rp
        addr,ip = dlookup(img, rp, name, None)
        if (ip == None):
            return None
        if (path == ""):
            return addr,ip
        if (int.from_bytes(ip[:2],"little") != T_DIR):
            return None
        rp = ip

def iread(img, dp, DE, off):
    if int.from_bytes(dp[:2],"little") == T_DEV:
        return -1
    size = int.from_bytes(dp[8:12],"little")
    """
    if off > size or off + DE < off:
        return -1
    """
    if off + DE > size:
        DE = size - off
    addr = bmap(img,dp,off//DE)
    de = img[addr * BSIZE:addr * BSIZE + BSIZE]
    return de
    
    
def iunlink(img, rp, path):
    name = ""
    zero = 0x00
    while True:
        assert path != "" and rp != None and int.from_bytes(rp[:2],"little") == T_DIR,"hah"
        path = skipelem(path,name)
        if name == "":
            os.error()
            return -1
        ip = dlookup(img,rp,name,None)
        if ip != None and path == "":
            if name == "." or name == "..":
                os.error()
                return -1
            if int.from_bytes(ip[:2],"little") == T_DIR and dlookup(img,ip,"..",None) == rp:
                rp[]
            

def dlookup(img, dp,name,offp):
    assert int.from_bytes(dp[:2],"little") == T_DIR,"ha"
    size = int.from_bytes(dp[8:12],"little")
    for i in range(0,size,SIZE_DE):
        de = iread(img, dp, SIZE_DE, i)
        for j in range(0,BSIZE,SIZE_DE):
            if(name == de[2+j:16+j].decode().replace('\x00',"")):
                if offp != None:
                    offp = i
                print(int.from_bytes(de[j:j+2],"little"),de[2+j:16+j].decode().replace('\x00',""))
                return int.from_bytes(de[j:j+2],"little"),iget(img,int.from_bytes(de[j:j+2],"little"))
    return None



def o_ls(img,args):
    if len(args) != 1:
        return 1
    path = args[0]

    addr,ip = ilookup(img, root_inode, path)
    if ip == None:
        os.error()
        return 1
    if int.from_bytes(ip[:2],"little") == T_DIR:
        for i in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
            flag,de = iread(img, ip, SIZE_DE, i)
            if int.from_bytes(de[:2],"little") == 0:
                continue
            for j in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
                p = iget(img,int.from_bytes(de[j:2+j],"little"))
                if p == None:
                    break
                print("{0} {1} {2} {3}".format(de[2+j:16+j].decode().replace('\x00',""),int.from_bytes(p[:2],"little"),int.from_bytes(de[j:2+j],"little"),int.from_bytes(p[8:12],"little")))
    else:
        print("{0} {1} {2} {3}".format(path,int.from_bytes(ip[:2],"little"),addr,int.from_bytes(ip[8:12],"little")))



def o_get(fd,args):
    if len(args) != 2:
        os.error()
        return 1








def o_put(fd,args):
    if len(args) != 2:
        os.error()
        return 1





def o_rm(fd,args):
    if len(args) != 1:
        os.error()
        return 1
    path = args[0]

    addr,ip = ilookup(img,root_inode,path)

    if ip == None:
        os.error()
        return 1
    if int.from_bytes(ip[:2],"little") == T_DIR:
        os.error()
        return 1
    if iunlink(img, root_inode, path) < 0:
        os.error()
        return 1
    return 0
    




def ofs():
    global root_inode
    args = sys.argv
    progname = args[0]
    if len(args) <= 3 or len(args) > 6:
        exit()

    img_file = args[1]
    cmd = args[2]


    #try:
    img_fd = os.open(img_file,os.O_RDWR)
    if img_fd < 0:
        exit()
    img_stat = os.fstat(img_fd)
    img_size = img_stat.st_size
    img = mmap.mmap(img_fd,img_size,mmap.MAP_SHARED,mmap.PROT_READ|mmap.PROT_WRITE,0)
    iii = img[1024:1028]
    if hex(int.from_bytes(iii,"little")) != "0x10203040":
        os.error()
    root_inode = iget(img,root_inode_number)
    #print("{0} {1} {2} {3} {4}".format(int.from_bytes(root_inode[:2],"little"),int.from_bytes(root_inode[2:4],"little"),int.from_bytes(root_inode[4:6],"little"),int.from_bytes(root_inode[6:8],"little"),int.from_bytes(root_inode[8:12],"little")))
    
    for cm in command:
        if cm[0] == cmd:
            end = handler(eval(cm[1]),img,args[3:])

    #else:


    """            
    except Exception:
        print(sys.exc_info()[0])
        exit()
    """
    os.close(img_fd)
    exit(end)

if __name__ == "__main__":
    ofs()
