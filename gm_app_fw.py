#!/usr/bin/env python
# Author zzerrg.no.more@gmail.com (c) 2016
# License: Apache License 2.0
# Source repo: https://github.com/zzerrg/gmfwtools

from __future__ import print_function
import os
import re
import sys
import binascii
import hashlib
import argparse
import ctypes
import time
from Crypto.Cipher import DES

B4 = ctypes.c_uint8 * 4
C16 = ctypes.c_char * 16
C32 = ctypes.c_char * 32


class GMAppFwHDR(ctypes.Structure):
    _fields_ = [
        ('z00', ctypes.c_uint32),     # 0x00000000
        ('jffs_sz', ctypes.c_uint32),  # JFFS image size
        ('exec_sz', ctypes.c_uint32),  # 0x1b21 - 14.0.0.x, 0x1ad5 - 21.0.0.x
        ('csum', C16),
        ('fw_ver', B4),
    ]
GMAppFwHDR_p = ctypes.POINTER(GMAppFwHDR)


class GMAppFirmware(object):

    DES_KEY = {
       14 : "\x9C\xAE\x6A\x5A\xE1\xFC\xB0\x88",  # specific for 14.0.0.x
       22 : "\x9c\xae\x6a\x5a\xe1\xfc\xb0\xa8"   # specific for 22.0.0.x
    }

    EXEC_SZ = {
       13 : 0x19c7,
       14 : 0x1b21,
       21 : 0x1ad5,
       22 : 0x18c7
    }


    def __init__(self, firmware_fn, offset=0, verbose=False, fw_version=None):
        self.fw_version = fw_version  # used in do_pack()
        self.offset = offset
        self.verbose = verbose
        self.firmware_fn = firmware_fn
        # assert os.path.exists(self.firmware_fn)
        self.h_buf = None
        self.hdr = None
        self.fw_jffs = None
        self.md5 = None
        self.fw_sig = None

    def des_key(self):
        ver_major = self.hdr.fw_ver[3]
        if ver_major not in self.DES_KEY:
            raise Exception("No DES key for version {}".format(ver_major))
        return self.DES_KEY[ver_major]

    def read_fw(self):
        with open(self.firmware_fn, 'rb') as fi:
            # fsize = fi.seek(0, 2)
            fi.seek(self.offset)
            self.h_buf = fi.read(0x20)
            hdr_a = ctypes.cast(ctypes.c_char_p(self.h_buf), GMAppFwHDR_p)
            self.hdr = hdr_a[0]
            assert self.hdr.exec_sz in self.EXEC_SZ.values(), \
                "Got unknown exec_sz = 0x%04x" % self.hdr.exec_sz
            fw_blob = fi.read()
            self.md5 = hashlib.md5()
            self.md5.update(fw_blob)
            j_sz = self.hdr.jffs_sz
            self.fw_jffs = fw_blob[0:j_sz]
            self.fw_exec = fw_blob[j_sz:j_sz+self.hdr.exec_sz]

    def check_signature(self, exit_on_fail=False):
        cipher = DES.new(self.des_key(), DES.MODE_ECB)
        md5d = self.md5.digest()
        sig0 = cipher.decrypt(md5d[0:8])
        sig1 = cipher.decrypt(md5d[8:16])
        self.fw_sig = str(sig0 + sig1)
        # if self.verbose:
        #    print("ECB dec: %s %s" %
        #          (binascii.b2a_hex(sig0), binascii.b2a_hex(sig1)))
        is_ok = self.fw_sig == str(self.hdr.csum)
        if not is_ok and exit_on_fail:
            print("%s: fw signature mismatch" % self.firmware_fn,
                  file=sys.stderr)
            sys.exit(os.EX_DATAERR)
        return is_ok

    def calc_fw_signature(self):
        cipher = DES.new(self.des_key(), DES.MODE_ECB)
        md5d = self.md5.digest()
        sig0 = cipher.decrypt(md5d[0:8])
        sig1 = cipher.decrypt(md5d[8:16])
        self.fw_sig = str(sig0 + sig1)

    def do_verify(self):
        self.read_fw()
        v = self.hdr.fw_ver
        print("fw_ver : %02d.%02d.%02d.%02d" %
              (v[3], v[2], v[1], v[0]))
        print("jffs sz: %d" % len(self.fw_jffs))
        print("exec sz: %d" % len(self.fw_exec))
        print("csum   : %s" % binascii.b2a_hex(self.hdr.csum))
        if self.verbose:
            # print("csum   : %s %s" %
            #       (binascii.b2a_hex(self.hdr.csum[0:8]),
            #        binascii.b2a_hex(self.hdr.csum[8:16])))
            print("des key: %s" % binascii.b2a_hex(self.des_key()))
            # print("key len: %d" % len(key))
            print("md5    : %s" % (self.md5.hexdigest()))
        is_ok = self.check_signature()
        print("sig ok : %s" % is_ok)
        return is_ok

    def do_unpack(self, out_fn, exec_fn):
        self.read_fw()
        self.check_signature(exit_on_fail=True)
        if not out_fn:
            v = self.hdr.fw_ver
            out_fn = ('app_%02d.%02d.%02d.%02d.jffs' %
                      (v[3], v[2], v[1], v[0]))
        print("Write APP JFFS image into %s" % out_fn)
        with open(out_fn, 'wb') as fo:
            fo.write(self.fw_jffs)
        if exec_fn is None:
            exec_fn = ('upg_%02d.%02d.%02d.%02d.elf' %
                       (v[3], v[2], v[1], v[0]))
        print("Write APP EXEC image into %s" % exec_fn)
        with open(exec_fn, 'wb') as fo:
            fo.write(self.fw_exec)

    def do_mount(self, mtdblockdev='/dev/mtdblock0', mpoint='/mnt/fw_app'):
        """
        # http://www.infradead.org/pipermail/linux-mtd/2006-April/015262.html
        modprobe mtdram total_size=16384 erase_size=64
        modprobe mtdblock
        dd if=unpacked.jffs of=/dev/mtdblock0
        mount -t jffs2 /dev/mtdblock0 /mnt/gw/app21/
        """
        self.read_fw()
        self.check_signature(exit_on_fail=True)
        self.safe_umount(mtdblockdev)
        self.load_kernel_modules()
        with open(mtdblockdev, 'wb') as fo:
            fo.write(self.fw_jffs)
        self.safe_mount(mtdblockdev, mpoint)

    def safe_mount(self, mtdblockdev, mountpoint):
        self.safe_umount(mtdblockdev)
        if not os.path.exists(mountpoint):
            os.mkdir(mountpoint)
        cmd = 'mount -t jffs2 %s %s' % (mtdblockdev, mountpoint)
        print(cmd)
        rc = os.system(cmd)
        assert rc == 0, "%s failed" % cmd

    def check_mount(self, mtdblockdev):
        need_umount = False
        with open('/proc/mounts', 'r') as mtab_fi:
            for line in mtab_fi.readlines():
                if line.startswith('%s ' % mtdblockdev):
                    need_umount = True
                    break
        return need_umount

    def safe_umount(self, mtdblockdev):
        if self.check_mount(mtdblockdev):
            cmd = 'umount %s' % mtdblockdev
            print(cmd)
            rc = os.system(cmd)
            assert rc == 0, "%s failed" % cmd

    def load_kernel_modules(self, ramsize=16384, eraseblock=64):
        has_mtdram = False
        has_mtdblock = False
        with open('/proc/modules', 'r') as mod_fi:
            for mod in mod_fi.readlines():
                if mod.startswith('mtdram '):
                    has_mtdram = True
                elif mod.startswith('mtdblock '):
                    has_mtdblock = True
        if not has_mtdram:
            cmd = ('modprobe mtdram total_size=%d erase_size=%d' %
                   (ramsize, eraseblock))
            print(cmd)
            rc = os.system(cmd)
            assert rc == 0, "%s failed" % cmd
            time.sleep(0.5)
        if not has_mtdblock:
            cmd = 'modprobe mtdblock'
            print(cmd)
            rc = os.system(cmd)
            assert rc == 0, "%s failed" % cmd
            time.sleep(0.5)

    def do_pack(self, jffs_fn, exec_fn):
        print("Pack %s + %s into FW image ..." % (jffs_fn, exec_fn))
        with open(exec_fn, 'rb') as fi:
            self.fw_exec = fi.read()
        with open(jffs_fn, 'rb') as fi:
            self.fw_jffs = fi.read()
        self.md5 = hashlib.md5()
        fw_blob = self.fw_jffs + self.fw_exec
        self.md5.update(fw_blob)
        self.calc_fw_signature()
        self.pack_header()
        print("Calculated fw_sig: %s" %
              binascii.b2a_hex(self.fw_sig))
        with open(self.firmware_fn, 'wb') as fo:
            buf = C32()
            ctypes.memmove(ctypes.addressof(buf), ctypes.addressof(self.hdr),
                           32)
            # print(binascii.b2a_hex(buf))
            fo.write(buf)
            fo.write(fw_blob)

    def pack_header(self):
        self.hdr = GMAppFwHDR()
        self.hdr.z00 = 0
        self.hdr.jffs_sz = len(self.fw_jffs)
        self.hdr.exec_sz = len(self.fw_exec)
        self.hdr.csum = self.fw_sig
        if self.fw_version is None:
            # default is 14.0.0.75
            self.hdr.fw_ver = B4(75, 0, 0, 14)
        else:
            m = re.match(r'(14)\.(0+)\.(\d+)\.(\d+)', self.fw_version)
            if not m:
                raise RuntimeError("%s: incorrect version" % self.fw_version)
            v1 = int(m.group(1))
            v2 = int(m.group(2))
            v3 = int(m.group(3))
            v4 = int(m.group(4))
            self.hdr.fw_ver = B4(v4, v3, v2, v1)
        print("Build FW version {3}.{2}.{1}.{0}".format(*(self.hdr.fw_ver)))


def main():
    parser = argparse.ArgumentParser(prog='gm_app_fw.py')
    parser.add_argument('-f', dest='fn',
                        help='file name fw binary',
                        required=True)
    parser.add_argument('-O', '--offset', dest='offset')
    parser.add_argument('-o', '--out', dest='out_fn')
    parser.add_argument('-j', '--jffs', dest='jffs_image',
                        help='file name of JFFS2 image')
    parser.add_argument('-e', '--exec', dest='exec_fn',
                        help='file name of newStart exec file')
    parser.add_argument('-V', '--version', dest='fw_version',
                        help='FW version, should match 14.0.N.N pattern')
    parser.add_argument('-d', '--debug', action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--verify', action='store_true')
    group.add_argument('-u', '--unpack', action='store_true')
    group.add_argument('-m', '--mount', action='store_true')
    group.add_argument('-p', '--pack', action='store_true')
    args = parser.parse_args()
    if args.offset:
        if args.offset[0:2] == '0x':
            offset = int(args.offset[2:], 16)
        else:
            offset = int(args.offset)
    else:
        offset = 0
    fw = GMAppFirmware(args.fn, offset=offset, verbose=args.debug,
                       fw_version=args.fw_version)
    if args.verify:
        is_ok = fw.do_verify()
        sys.exit(os.EX_OK if is_ok else os.EX_DATAERR)
    elif args.unpack:
        fw.do_unpack(args.out_fn, args.exec_fn)
    elif args.mount:
        fw.do_mount()
    elif args.pack:
        fw.do_pack(args.jffs_image, args.exec_fn)
    else:
        print("Usage: one of -v, -u or -p options should be specified")
        sys.exit(os.EX_USAGE)


if __name__ == '__main__':
    main()
