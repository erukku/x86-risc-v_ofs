import sys,os,mmap,binascii
from struct import *

magicfs = 0x10203040

BSIZE = 1024
DATA = 46
IB = 32
BB = 45
IPB = 16
BPB = (BSIZE*8)
ninodes = 200
root_inode_number = 1
#fatal_exception_buf
command = [["ls","o_ls"],["get","o_get"],["put","o_put"],["rm","o_rm"]]
DIRSIZ = 14

SIZE_DE = 16

NDIRECT = 12

NINDIRECT = BSIZE // 4

MAXFILE = NDIRECT + NINDIRECT

T_DIR = 1
T_FILE = 2
T_DEV = 3

root_inode = 0

def divceil(x,y):
    return (x + y - 1) // y





def bfree(img,b):

    
    bi = b % BPB
    m = 1 << (bi % 8)
    #if ((bp[bi / 8] & m) == 0):
    
    img[((b)//BPB + BB)*BSIZE + (bi / 8):((b)//BPB + BB)*BSIZE + (bi / 8)+4] = (int.from_bytes( img[((b)//BPB + BB)*BSIZE + (bi / 8):((b)//BPB + BB)*BSIZE + (bi / 8)+4],"little") & ~m).to_bytes(4,'little')
    return 0


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


def itruncate(img,ip,size):
    if (int.from_bytes(ip[:2],"little") == T_DEV):
        return -1;
    if (size > MAXFILE):
        return -1;
    if size < int.from_bytes(ip[8:12],"little"):
        n = divceil(int.from_bytes(ip[8:12],"little"), BSIZE)
        k = divceil(size, BSIZE)
        nd = min(n,NDIRECT)
        kd = min(k,NDIRECT)
        for i in range(kd,nd):
            bfree(img, int.from_bytes(ip[12 + i * 4:12 + (i + 1) * 4],"little"))
            ip[12 + 4 * i:12 + 4 * (i+1)] = [0x00]*4
        if n > NDIRECT:
            iaddr = int.from_bytes(ip[12 + NDIRECT*4:12+ (NDIRECT+1)*4],"little")
            iip = img[iaddr*BSIZE:iaddr*BSIZE + BSIZE]
            assert(iaddr != 0)
            ni = max(n - NDIRECT, 0);
            ki = max(k - NDIRECT, 0);
            for i in range(ki,ni):
                bfree(img, iip[i:i + 4]);
                iblock[i] = 0;
            if ki == 0:
                bfree(img, iaddr);
                ip[12 + NDIRECT*4:12+ (NDIRECT+1)*4] = [0x00]*4;
    ip[8:12] = [0x00] * 4
    return 0;


def ifree(img,inum):
    ip = iget(img,inum)
    if ip == None:
        return -1
    if int.from_bytes(ip[:2],"little") == 0:
        return -1
    if int.from_bytes(ip[4:6],"little") > 0:
        return -1
    img[(IB + inum//IPB) * 1024 + (inum % IPB) * 64:(IB + inum//IPB) * 1024 + (inum % IPB) * 64 + 2] = [0x00]*2
    return 0
    

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

def iwrite(img, dp):
    if int.from_bytes(dp[:2],"little") == T_DEV:
        return -1
    size = int.from_bytes(dp[8:12],"little")
    addr = bmap(img,dp,off//DE)
    img[addr * BSIZE:addr * BSIZE + BSIZE] = [0x00]*BSIZE
    return 0
    
    
def iunlink(img, rp, path):
    name = ""
    zero = 0x00
    while True:
        assert path != "" and rp != None and int.from_bytes(rp[:2],"little") == T_DIR,"hah"
        path = skipelem(path,name)
        if name == "":
            os.error()
            return -1
        addr,ip = dlookup(img,rp,name,None)
        if ip != None and path == "":
            if name == "." or name == "..":
                os.error()
                return -1
            if iwrite(img,ip) != 0:
                os.error()
            if int.from_bytes(ip[:2],"little") == T_DIR and dlookup(img,ip,"..",None) == rp:
                rp[4:6] = (int.from_bytes(rp[4:6],"little") - 1).to_bytes(2, 'little')
            ip[4:6] = (int.from_bytes(ip[4:6],"little") - 1).to_bytes(2, 'little')
            if int.from_bytes(ip[4:6],"little") == 0:
                if int.from_bytes(ip[:2],"little") != T_DEV:
                    itruncate(img, ip, 0)
                ifree(img, addr)
                return 0
        if ip == None or int.from_bytes(rp[:2],"little") != T_DIR:
            return -1
        rp = ip

            

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



def o_get(img,args):
    if len(args) != 2:
        os.error()
        return 1
    fspath = args[0]
    outpath = args[1]

    ip = ilookup(img, root_inode, fspath)
    with open(outpath, "w") as f:
        st = ""
        for i in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
            flag,de = iread(img, ip, SIZE_DE, i)
            if int.from_bytes(de[:2],"little") == 0:
                continue
            for j in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
                p = iget(img,int.from_bytes(de[j:2+j],"little"))
                if p == None:
                    break
                st += de[2+j:16+j].decode().replace('\x00',"")
            f.write(st)
    return 0









def o_put(img,args):
    if len(args) != 2:
        os.error()
        return 1
    fspath = args[0]
    outpath = args[1]
    ip = ilookup(img, root_inode, fspath)
    with open(outpath, "r") as f:
        if ip == None:
            ip = icreat(img, root_inode, path, T_FILE, NULL)
            if ip == None:
                return -1
        else:
            if int.from_bytes(de[:2],"little") != T_FILE:
                return -1
            itruncate(img, ip, 0)
        




def o_rm(img,args):
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
