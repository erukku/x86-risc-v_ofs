import sys,os,mmap,binascii,copy
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
command = [["ls","o_ls"],["get","o_get"],["put","o_put"],["rm","o_rm"],["info","o_info"],["diskinfo","o_diskinfo"],["ln","o_ln"],["mkdir","o_mkdir"],["rmdir","o_rmdir"]]
DIRSIZ = 14

SIZE_DE = 16
BUFSIZE = 1024
NDIRECT = 12

NINDIRECT = BSIZE // 4

MAXFILE = NDIRECT + NINDIRECT

T_DIR = 1
T_FILE = 2
T_DEV = 3

root_inode = 0

N = 0
Nl = 0
Ni = 0
Nm = 0
Nd = 0

logstart = 0
inodestart = 0
bmapstart = 0
datastart = 0

def divceil(x,y):
    return (x + y - 1) // y


def bfree(img,b):
    bi = b % BPB
    m = 1 << (bi % 8)
    
    img[((b)//BPB + BB)*BSIZE + (bi // 8):((b)//BPB + BB)*BSIZE + (bi // 8)+1] = (int.from_bytes(img[((b)//BPB + BB)*BSIZE + (bi // 8):((b)//BPB + BB)*BSIZE + (bi // 8)+1],"little") & ~m).to_bytes(1,'little')
    
    return 0


def bmap(img,ip,baddr,n):
    if n < NDIRECT:
        addr = int.from_bytes(ip[12+4*n:12+4*(n+1)],"little")

        if addr == 0:
            addr = balloc(img);
            img[baddr + 12 + n * 4:baddr + 12 + (n+1) * 4] = addr.to_bytes(4,"little")
        return addr

    else:
        k = n - NDIRECT
        if(k >= NINDIRECT):
            os.error("invalid index number")
        iaddr = int.from_bytes(ip[12+4*NDIRECT:12+4*(NDIRECT+1)],"little")

        if iaddr == 0:
            addr = balloc(img);
            img[baddr + 12 + NDIRECT * 4:baddr + 12 + (NDIRECT+1) * 4] = iaddr.to_bytes(4,"little")
        dp =  int.from_bytes(img[iaddr*BSIZE+k*4:iaddr*BSIZE+(k+1)*4],"little")

        if dp == 0:
            dp = balloc(img);
            img[iaddr*BSIZE+k*4:iaddr*BSIZE+(k+1)*4] = dp.to_bytes(4,"little")
        return dp

def balloc(img):
    for i in range(0,N,BPB):
        bb = img[(BB+i)*BSIZE:(BB+i+1)*BSIZE]
        for ii in range(0,N-i):
            bbb = bb[ii//8:ii//8 + 1]
            if not ii < BPB:
                break
            m = 1 << (ii % 8)
            if (int.from_bytes(bbb,"little") & m) == 0:
                img[(BB+i)*BSIZE+ii//8:(BB+i)*BSIZE+ii//8 + 1] = (int.from_bytes(bbb,"little") | m).to_bytes(1,"little")
                a = 0
                img[(ii)*BSIZE:(ii+1)*BSIZE] = a.to_bytes(BSIZE,"little")
                return ii
    return 0

        
def daddent(img, dp, daddr,name,addr):
    flag = False
    addrs = 0
    j = 0
    daddr = (IB + daddr//IPB) * 1024 + (daddr % IPB) * 64
    for i in range(0,int.from_bytes(dp[8:12],"little")+SIZE_DE-1,SIZE_DE):
        addrs,de = iread(img, dp, daddr,SIZE_DE, i)
        for j in range(0,BSIZE,SIZE_DE):
            if int.from_bytes(de[j:2+j],"little") == 0:
                flag = True
                break
            if(name.replace('\x00',"") == de[2+j:16+j].decode().replace('\x00',"")):
                os.error("daddent: {0}: exists".format(name))
                return -1;
        if flag:
            break
    for i in range(14-len(name)):
        name += "\0"
    j //= SIZE_DE
    img[daddr+8:daddr+12] = (int.from_bytes(img[daddr+8:daddr+12],"little") + 16).to_bytes(4,"little")
    img[addrs * BSIZE + j*SIZE_DE+2:addrs * BSIZE + j*SIZE_DE+16] = name.encode()
    img[addrs * BSIZE + j*SIZE_DE:addrs * BSIZE + j*SIZE_DE+2] = addr.to_bytes(2,"little")
    
    if name.replace('\x00',"") != ".":
        addr = (IB + addr//IPB) * 1024 + (addr % IPB) * 64
        img[addr+6:addr+8] = (int.from_bytes(img[addr+6:addr+8],"little")+1).to_bytes(2,"little")
    return 0



def handler(func,fd,*args):
    return func(fd,*args)

def icreat(img, rp, raddr,path, type, dpp):
    name = ""
    while True:
        assert path != "" and rp != None and int.from_bytes(rp[:2],"little") == T_DIR,"h"
        path,name = skipelem(path, name)
        if (name.replace('\x00',"") == ""):
            os.error("icreat: {0}: empty file name".format(name))
            return None,None

        dnum,addr,ip = dlookup(img, rp, raddr,name, None)
        if path == None:
            if ip != None:
                os.error("icreat: {0}: file exists".format(name))
                return None,None

            addr,ip = ialloc(img, type)
            daddent(img, rp, raddr,name, addr)
            if (int.from_bytes(ip[:2],"little") == T_DIR):
                dnum,addr,ip = dlookup(img, rp, raddr,name, None)
                daddent(img, ip, addr,".", addr)
                dnum,addr,ip = dlookup(img, rp, raddr,name, None)
                daddent(img, ip, addr,"..", raddr)
            if (dpp != None):
                dpp = rp
            return addr,ip
        if ip == None or int.from_bytes(ip[:2],"little") != T_DIR:
            os.error("icreat: {0}: no such directory".format(name))
            return None,None
        rp = ip
        raddr = addr

def ialloc(img,type):
    for i in range(1,ninodes):
        ip = iget(img,i)
        if int.from_bytes(ip[:2],"little") == 0:
            a = 0
            img[(IB + i//IPB) * 1024 + (i % IPB) * 64:(IB + i//IPB) * 1024 + (i % IPB) * 64 + 64] = a.to_bytes(64,"little")
            img[(IB + i//IPB) * 1024 + (i % IPB) * 64:(IB + i//IPB) * 1024 + (i % IPB) * 64 + 2] = type.to_bytes(2,"little")
            return  i,img[(IB + i//IPB) * 1024 + (i % IPB) * 64:(IB + i//IPB) * 1024 + (i % IPB) * 64 + 64]
    return None

def iget(img,inum):
    if 0 < inum and inum < ninodes:
        gg = img[(IB + inum//IPB) * 1024 + (inum % IPB) * 64:(IB + inum//IPB) * 1024 + (inum % IPB) * 64 + 64]
        return gg
    return None


def skipelem(path,name):
    for i in range(len(path)):
        if path[i] != "/":
            path = path[i:]
            break
    else:
        path = None
    nm = ""
    if path != None:
        for i in range(min(len(path),DIRSIZ)):
            if path[i] != "/":
                nm += path[i]
            else:
                path = path[i+1:]
                break
        else:
            path = None
    else:
        nm = None
    return path,nm


def itruncate(img,ip,addr,size):
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
            a = 0
            img[(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 12 + 4 * i:(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 12 + 4 * (i+1)] = a.to_bytes(4,"little")
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
                a = 0
                ip[12 + NDIRECT*4:12+ (NDIRECT+1)*4] = a.to_bytes(4,"little");
                img[(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 12 + NDIRECT*4:(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 12+ (NDIRECT+1)*4] = a.to_bytes(4,"little")
    
    a = 0
    img[(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 8:(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 12] = a.to_bytes(4,"little")
    return 0;


def ifree(img,inum):
    ip = iget(img,inum)
    if ip == None:
        return -1
    if int.from_bytes(ip[:2],"little") == 0:
        return -1
    if int.from_bytes(ip[6:8],"little") > 0:
        return -1
    a = 0
    img[(IB + inum//IPB) * 1024 + (inum % IPB) * 64:(IB + inum//IPB) * 1024 + (inum % IPB) * 64 + 2] = a.to_bytes(2,"little")
    return 0
    

def ilookup(img,rp, raddr,path):
    name = ""
    while True:
        if path != None and rp != None and int.from_bytes(rp[:2],"little") != T_DIR:
            os.error()
        path,name = skipelem(path, name)
        if(name == None):
            return raddr,rp
        dnum,addr,ip = dlookup(img, rp, raddr,name, None)
        if (ip == None):
            return None,None
        if (path == None):
            return addr,ip
        if (int.from_bytes(ip[:2],"little") != T_DIR):
            return None,None
        rp = ip
        raddr = addr

def iread(img, dp, daddr,DE, off):
    if int.from_bytes(dp[:2],"little") == T_DEV:
        return -1
    size = int.from_bytes(dp[8:12],"little")
    """
    if off > size or off + DE < off:
        return -1
    """
    if off + DE > size:
        DE = size - off
    addr = bmap(img,dp,daddr,off//SIZE_DE)
    de = img[addr * BSIZE:addr * BSIZE + BSIZE]
    return addr,de

def iwrite(img,dp,name,off):
    if int.from_bytes(dp[:2],"little") == T_DEV:
        return -1
    de = img[off * BSIZE:(off+1) * BSIZE]
    for j in range(0,BSIZE,SIZE_DE):
        if(name.replace('\x00',"") == de[2+j:16+j].decode().replace('\x00',"")):
            a = 0
            j //= SIZE_DE
            img[off * BSIZE + j*SIZE_DE:off * BSIZE + (j+1)*SIZE_DE] = a.to_bytes(16, 'little')
            break
    off -= 1
    return 0
    
    
def iunlink(img, addrs, path):
    name = ""
    zero = 0x00
    rp = iget(img,addrs)
    while True:
        assert path != "" and rp != None and int.from_bytes(rp[:2],"little") == T_DIR,"hah"
        path,name = skipelem(path,name)
        if name == "":
            os.error("iunlink: empty file name")
            return -1
        dnum,addr,ip = dlookup(img,rp,addrs,name,None)
        if ip != None and path == None:
            if name == "." or name == "..":
                os.error("iunlink: cannot unlink \".\" or \"..\"")
                return -1
            if iwrite(img,rp,name,dnum) != 0:
                os.error("iunlink: write error")
            if int.from_bytes(ip[:2],"little") == T_DIR and dlookup(img,ip,addr,"..",None)[2] == rp:
                img[(IB + addrs//IPB) * 1024 + (addrs % IPB) * 64 + 6:(IB + addrs//IPB) * 1024 + (addrs % IPB) * 64 + 8] = (int.from_bytes(rp[6:8],"little") - 1).to_bytes(2, 'little')
                rp = iget(img,addrs)
            img[(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 6:(IB + addr//IPB) * 1024 + (addr % IPB) * 64 + 8] = (int.from_bytes(ip[6:8],"little") - 1).to_bytes(2, 'little')
            ad = int.from_bytes(ip[6:8],"little") - 1
            if ad == 0:
                if int.from_bytes(ip[:2],"little") != T_DEV:
                    itruncate(img, ip,addr,0)
                ifree(img, addr)
                return 0
        if ip == None or int.from_bytes(rp[:2],"little") != T_DIR:
            return -1
        rp = ip
        addrs = addr

            

def dlookup(img, dp,daddr,name,offp):
    assert int.from_bytes(dp[:2],"little") == T_DIR,"ha"
    size = int.from_bytes(dp[8:12],"little")
    for i in range(0,size,BSIZE):
        addr,de = iread(img, dp, daddr,SIZE_DE, i)
        for j in range(0,BSIZE,SIZE_DE):
            if(name.replace('\x00',"") == de[2+j:16+j].decode().replace('\x00',"")):
                if offp != None:
                    offp = i
                return addr,int.from_bytes(de[j:j+2],"little"),iget(img,int.from_bytes(de[j:j+2],"little"))
    return None,None,None


def typename(type):
    if type == T_DIR:
        return "T_DIR"
    elif type == T_FILE:
        return "T_FILE"
    elif type == T_DEV:
        return "T_DEV"
    else:
        return "Unkown"


def o_ls(img,args):
    if len(args) != 1:
        print("usage: img_file ls path")
        return 1
    path = args[0]
    root_inodes = iget(img,root_inode_number)
    addr,ip = ilookup(img, root_inodes, root_inode_number,path)
    if ip == None:
        os.error("ls: {0}: no such file or directory".format(path))
        return 1
    if int.from_bytes(ip[:2],"little") == T_DIR:
        for i in range(0,int.from_bytes(ip[8:12],"little"),BSIZE):
            flag,de = iread(img, ip, addr,SIZE_DE, i)
            if int.from_bytes(de[:2],"little") == 0:
                continue
            for j in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
                p = iget(img,int.from_bytes(de[j:2+j],"little"))
                if p == None:
                    continue
                print("{0} {1} {2} {3}".format(de[2+j:16+j].decode().replace('\x00',""),int.from_bytes(p[:2],"little"),int.from_bytes(de[j:2+j],"little"),int.from_bytes(p[8:12],"little")))
    else:
        print("{0} {1} {2} {3}".format(path,int.from_bytes(ip[:2],"little"),addr,int.from_bytes(ip[8:12],"little")))



def o_get(img,args):
    if len(args) != 2:
        print("usage: img_file get innerpath outerpath")
        return 1
    fspath = args[0]
    outpath = args[1]
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img, root_inode, root_inode_number,fspath)
    print("{0} {1} {2} {3}".format(fspath,int.from_bytes(ip[:2],"little"),addr,int.from_bytes(ip[8:12],"little")))
    with open(outpath, "w") as f:
        st = ""
        for i in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
            flag,de = iread(img, ip, addr,SIZE_DE, i)
            for j in range(0,int.from_bytes(ip[8:12],"little"),SIZE_DE):
                st += de[j:16+j].decode().replace('\x00',"")
        f.write(st)
    return 0



def o_put(img,args):
    if len(args) != 2:
        print("usage: img_file put outerpath innerpath")
        return 1
    fspath = args[1]
    inpath = args[0]
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img, root_inode, root_inode_number,fspath)
    with open(inpath, "r") as f:
        s = f.read()
        if ip == None:
            addr,ip = icreat(img, root_inode,root_inode_number,fspath, T_FILE, None)
            if ip == None:
                return -1
        else:
            if int.from_bytes(ip[:2],"little") != T_FILE:
                return -1
            itruncate(img, ip,addr, 0)
        da = 0
        addr = (IB + addr//IPB) * 1024 + (addr % IPB) * 64
        for i in range(0,MAXFILE):
            ii = i
            iaddr = bmap(img,ip,addr,ii)
            leng = min(BSIZE,len(s))
            if len(img[iaddr * BSIZE:iaddr * BSIZE + leng]) == 0:
                break
            img[iaddr * BSIZE:iaddr * BSIZE + leng] = s[:leng].encode()
            img[addr+8:addr+12] = (int.from_bytes(img[addr+8:addr+12],"little") + leng).to_bytes(4,"little")
            s = s[leng:]
            if s == "":
                break
    return 0


def o_diskinfo(img,args):
    if len(args) != 0:
        print("usage: img_file diskinfo")
        return 1
    
    root_inode = iget(img,root_inode_number)

    print("magic: {0}".format(magicfs))
    print("total blocks: {0} ({1} bytes)".format(1000, 1000 * BSIZE))
    print("log blocks: #{0}-#{1} ({2} blocks)".format(2, 31, 30))
    print("inode blocks: #{0}-#{1} ({2} blocks, {3} inodes)".format(IB, 44, 13, 200))
    print("bitmap blocks: #{0}-#{1} ({2} blocks)".format(BB, BB, 1))
    print("data blocks: #{0}-#{1} ({2} blocks)".format(46, 999, 954))
    print("maximum file size (bytes): {0}".format(MAXFILE))

    nblocks = 0
    for i in range(BB + Nm):
        dd = img[BB+i:BB+i+1]
        for j in range(8):
            m = 1 << j
            if int.from_bytes(dd,"little") & m == 1:
                nblocks += 1
    print("# of used blocks: {0}".format(nblocks))

    n_dirs = 0
    n_files = 0
    n_devs = 0;
    for i in range(1,201):
        type = iget(img,i)
        if type == None:
            continue
        type = int.from_bytes(type[:2],"little")
        if type == T_DIR:
            n_dirs += 1
        elif type == T_FILE:
            n_files += 1
        elif type == T_DEV:
            n_devs += 1
    print("# of used inodes: {0} (dirs: {1}, files: {2}, devs: {3})".format(n_dirs + n_files + n_devs, n_dirs, n_files, n_devs))
    return 0;

def emptydir(img,dp):
    nent = 0
    for i in range(0,int.from_bytes(dp[8:12],"little"),SIZE_DE):
        if dp[12 + (i) * 4: + 12 + (i)+1 * 4] != 0:
            nent += 1
    return (nent == 2)

def splitpath(path, dirbuf, size):
    s = path
    t = path
    while not path == None:
        for i in range(len(path)):
            if path[i] != "/":
                path = path[i:]
                break
        else:
            path = None
        s = path
        for i in range(len(path)):
            if path[i] == "/":
                path = path[i:]
                break
        else:
            path = None
    
    if (dirbuf != None):
        dirbuf = t[:len(t)-len(s)]
    return s,dirbuf;

def o_info(img,args):
    path = args[0]
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img,root_inode,root_inode_number,path)
    if ip == None:
        print("usage: img_file info path")
        return 1
    print("inode: {0}".format(addr))
    print("type: {0} ({1})".format(int.from_bytes(ip[:2],"little"), typename(int.from_bytes(ip[:2],"little"))))
    print("nlink: {0}".format(int.from_bytes(ip[6:8],"little")))
    print("size: {0}".format(int.from_bytes(ip[8:12],"little")))

    if int.from_bytes(ip[8:12],"little") > 0:
        print("data blocks:")
        bcount = 0
        for i in range(NDIRECT):
            if int.from_bytes(ip[12+i*4:12+(i+1)*4],"little") == 0:
                break
            bcount += 1
            print(" {0}".format(int.from_bytes(ip[12+i*4:12+(i+1)*4],"little")),end = "")
        iaddr = int.from_bytes(ip[12+NDIRECT*4:12+(NDIRECT+1)*4],"little")
        if iaddr != 0:
            bcount += 1
            print(" {0}".format(iaddr),end = "")
            ib = img[iaddr:iaddr+64]
            for i in range(BSIZE//4):
                if int.from_bytes(ib[i*4:(i+1)*4],"little") == 0:
                    break
                bcount += 1
                print(" {0}".format(int.from_bytes(ib[i*4:(i+1)*4],"little")),end = "")
        print()
        print("# of data blocks: {0}".format(bcount))
        return 0
def o_rm(img,args):
    if len(args) != 1:
        print("usage: img_file rm path")
        return 1
    path = args[0]
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img,root_inode,root_inode_number,path)

    if ip == None:
        os.error("rm: {0}: no such file or directory".format(path))
        return 1
    if int.from_bytes(ip[:2],"little") == T_DIR:
        os.error("rm: {0}: a directory".format(path))
        return 1
    if iunlink(img, root_inode_number, path) < 0:
        os.error("rm: {0}: cannot unlink".format(path))
        return 1
    return 0


def o_ln(img,args):
    if len(args) != 2:
        print("usage: img_file ln path path")
        return 1
    frompath = args[0]
    topath = args[1]
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img,root_inode,root_inode_number,frompath)
    if ip == None:
        os.error("ln: {0}: no such file or directory".format(frompath))
        return 1
    if int.from_bytes(ip[:2],"little") != T_FILE:
        os.error("ln: {0}: is a directory or a device".format(frompath))
        return 1
    ddir = "";
    dname,ddir = splitpath(topath, ddir, BUFSIZE)
    daddr,dp = ilookup(img, root_inode,root_inode_number,ddir)
    if (dp == None):
        os.error("ln: {0}: no such directory".format(ddir))
        return 1
    if (int.from_bytes(dp[:2],"little") != T_DIR):
        os.error("ln: {0}: not a directory".format(ddir))
        return 1
    if (dname == None):
        dname,ddd = splitpath(frompath, None, 0)
        ddaddr,ddp = dlookup(img, dp, daddr, dname, None)
        if (ddp == None):
            os.error("ln: {0}/{1}: file exists".format(ddir, dname))
            return 1
    else:
        nn,ddr,ip = dlookup(img, dp,daddr, dname, None)
        if (ip != None):
            if (int.from_bytes(dp[:2],"little") != T_DIR):
                os.error("ln: {0}/{1}: file exists".format(ddir, dname))
                return 1
            dname,ddd = splitpath(frompath, None, 0)
            dp = ip
            daddr = ddr
    if (daddent(img, dp,daddr,dname, addr) < 0):
        os.error("ln: {0}/{1}: cannot create a link".format(ddir, dname))
        return 1
    return 0
    



def o_mkdir(img,args):
    if len(args) != 1:
        print("usage: img_file mkdir path")
        return 1
    path = args[0]
    
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img,root_inode,root_inode_number,path)
    
    if ip != None:
        os.error("mkdir: {0}: file exists".format(path))
        return 1
    
    addr,ip = icreat(img, root_inode,root_inode_number,path, T_DIR, None)
    if ip == None:
        os.error("mkdir: {0}: cannot create".format(path))
        return 1

    return 0

def o_rmdir(img,args):
    if len(args) != 1:
        print("usage: img_file rmdir path")
        return 1
    
    path = args[0]
    root_inode = iget(img,root_inode_number)
    addr,ip = ilookup(img,root_inode,root_inode_number,path)

    if ip == None:
        os.error("rmdir: {0}: no such file or directory".format(path))
        return 1
    
    if int.from_bytes(ip[:2],"little") != T_DIR:
        os.error("rmdir: {0}: not a directory".format(path))
        return 1

    if not emptydir(img,ip):
        os.error("rmdir: {0}: non-empty directory".format(path))
        return 1
    if iunlink(img, addr, path) < 0:
        os.error("rmdir: {0}: cannot unlink".format(path))
        return 1
    return 0


def ofs():
    global root_inode
    args = sys.argv
    progname = args[0]
    if len(args) < 3 or len(args) > 6:
        os.error("fail usage")
        exit()

    img_file = args[1]
    cmd = args[2]

    try:
        img_fd = os.open(img_file,os.O_RDWR)
        
        if img_fd < 0:
            os.error("nothing")
        img_stat = os.fstat(img_fd)
        img_size = img_stat.st_size

        img = mmap.mmap(img_fd,img_size,mmap.MAP_SHARED,mmap.PROT_READ|mmap.PROT_WRITE,0)
        iii = img[1024:1028]
        if hex(int.from_bytes(iii,"little")) != "0x10203040":
            os.error(": invalid magic number:")
        root_inode = iget(img,root_inode_number)

        global N,Nl,Ni,Nm,Nd,ninodes
        global logstart,inodestart,bmapstart,datastart

        N = int.from_bytes(img[1028:1032],"little")
        Nl = int.from_bytes(img[1040:1044],"little")
        Ni = int.from_bytes(img[1036:1040],"little") // IPB + 1
        Nm = N // (BSIZE * 8) + 1
        Nd = N - (1 + 1 + Ni + Nl + Nm)
        ninodes = int.from_bytes(img[1036:1040],"little")

        logstart = int.from_bytes(img[1044:1048],"little")
        inodesstart = int.from_bytes(img[1048:1052],"little")
        bmapstart = int.from_bytes(img[1052:1056],"little")
        datastart = bmapstart + Nm
        
        for cm in command:
            if cm[0] == cmd:
                end = handler(eval(cm[1]),img,args[3:])
    except Exception:
        print(sys.exc_info()[0])
        end = 1
    os.close(img_fd)
    exit(end)

if __name__ == "__main__":
    ofs()
