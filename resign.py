#!/usr/bin/python
from xml.dom import minidom
import re
import os
import mmap
import subprocess
import fnmatch
import argparse
import fileinput
import codecs

cwd = os.path.dirname(os.path.realpath(__file__))
useApkSigner = False # If you prefer, set this to Trueif you have apksigner installed


def find(pattern, path):
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                return os.path.join(root, name)


parser = argparse.ArgumentParser(
    description="Python Script to resign an Android ROM using custom keys")
parser.add_argument('RomDir', help='ROM Path. You can pass multiple folders, separated by comma')
parser.add_argument(
    'SecurityDir', help='Security Dir Path (just like https://android.googlesource.com/platform/build/+/master/target/product/security/)')
args = parser.parse_args()
itemlist = []
seinfos = []
mac_permissions = []
romdir = args.RomDir.split(',')
for i in range(len(romdir)):
    romdir[i] = os.path.abspath(romdir[i])
    #print (romdir[i])
    mac_permissions_file = find("*mac_permissions*", romdir[i] + "/etc/selinux")
    if mac_permissions_file != None:
        #print (mac_permissions_file)
        mac_permissions.append(mac_permissions_file)
        xmldoc = minidom.parse(mac_permissions_file)
        itemlist += xmldoc.getElementsByTagName('signer')
        for seinfo in xmldoc.getElementsByTagName('seinfo'):
            seinfos.append(seinfo.attributes['value'].value)
    
securitydir = os.path.abspath(args.SecurityDir)

certlen = len(itemlist)

signatures = []
signatures64 = []
usedseinfos = []

tmpdir = cwd + "/tmp"
signapkjar = cwd + "/signapk.jar"
os_info = os.uname()[0]
signapklibs = cwd + "/" + os_info


def CheckCert(filetoopen, cert):
    f = open(filetoopen)
    s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    if s.find(cert) != -1:
        return True
    else:
        return False


def getcert(jar, out):
    extractjar = "7z e " + jar + " META-INF/CERT.RSA -o" + tmpdir
    x = subprocess.run(
        ['7z', 't', jar], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if x.returncode == 0:
        output = subprocess.check_output(['bash', '-c', extractjar])

    if os.path.exists(tmpdir + "/CERT.RSA"):
        extractcert = "openssl pkcs7 -in " + tmpdir + \
            "/CERT.RSA -print_certs -inform DER -out " + out
        output = subprocess.check_output(['bash', '-c', extractcert])
        os.remove(tmpdir + "/CERT.RSA")


def sign(jar, certtype):
    if not os.path.exists(securitydir + "/" + certtype + ".pk8"):
        print((certtype + ".pk8 not found in security dir"))
        return False

    jartmpdir = tmpdir + "/JARTMP"
    if not os.path.exists(jartmpdir):
        os.makedirs(jartmpdir)

    signjarcmd = "java -XX:+UseCompressedOops -XX:+PerfDisableSharedMem -Xms2g -Xmx2g -Djava.library.path=" + signapklibs + " -jar " + signapkjar + " " + securitydir + \
        "/" + certtype + ".x509.pem " + securitydir + "/" + certtype + \
        ".pk8 " + jar + " " + jartmpdir + "/" + os.path.basename(jar)

    movecmd = "mv -f " + jartmpdir + "/" + os.path.basename(jar) + " " + jar
    try:
        output = subprocess.check_output(['bash', '-c', signjarcmd])
        output += subprocess.check_output(['bash', '-c', movecmd])
        print((os.path.basename(jar) + " signed as " + seinfo))
        usedseinfos.append(
            seinfo) if seinfo not in usedseinfos else usedseinfos
    except subprocess.CalledProcessError:
        print(("Signing " + os.path.basename(jar) + " failed"))


def zipalign(jar):
    jartmpdir = tmpdir + "/JARTMP"
    if not os.path.exists(jartmpdir):
        os.makedirs(jartmpdir)

    zipaligncmd = "zipalign -f -p 4 " + jar + " " + jartmpdir + "/" + os.path.basename(jar)

    movecmd = "mv -f " + jartmpdir + "/" + os.path.basename(jar) + " " + jar
    try:
        output = subprocess.check_output(['bash', '-c', zipaligncmd])
        output += subprocess.check_output(['bash', '-c', movecmd])
        print((os.path.basename(jar) + " zipaligned"))
    except subprocess.CalledProcessError:
        print(("Zipaligning " + os.path.basename(jar) + " failed"))

def apksign(jar, certtype):
    apksigncmd = "apksigner sign --key " + securitydir + "/" + certtype + ".pk8 --cert " + securitydir + "/" + certtype + ".x509.pem  " + jar
    #print (apksigncmd)
    try:
        output = subprocess.check_output(['bash', '-c', apksigncmd])
        print((os.path.basename(jar) + " apksigned"))
    except subprocess.CalledProcessError:
        print(("Apksigning " + os.path.basename(jar) + " failed"))

def recontext(jar):
    contextcmd = 'sudo setfattr -n security.selinux -v "u:object_r:system_file:s0" ' + jar
    try:
        output = subprocess.check_output(['bash', '-c', contextcmd])
        print("Restored context for " + (os.path.basename(jar)))
    except subprocess.CalledProcessError:
        print(("Restoring context for " + os.path.basename(jar) + " failed"))

index = 0
for s in itemlist:
    signatures.append(s.attributes['signature'].value)
    test64 = codecs.encode(codecs.decode(
        s.attributes['signature'].value, 'hex'), 'base64').decode()
    test64 = test64.replace('\n', '')

    signatures64.append(re.sub("(.{64})", "\\1\n", test64, 0, re.DOTALL))

if not os.path.exists(tmpdir):
    os.makedirs(tmpdir)

for romdirItem in romdir:
    for root, dirs, files in os.walk(romdirItem):
        for file in files:
            if file.endswith(".apk") or file.endswith(".jar") or file.endswith(".apex"):
                jarfile = os.path.join(root, file)

                os.chdir(tmpdir)
                out = "foo.cer"
                if os.path.exists(out):
                    os.remove(out)

                getcert(jarfile, out)
                if not os.path.exists(out):
                    print((file + " : No signature => Skip"))
                else:
                    index = 0
                    for seinfo in seinfos:
                        if CheckCert(out, signatures64[index].encode()):
                            #zipalign(jarfile) #zipalign not needed as already alligned. Old code called it after signing, and that was worse, as it messed up signature
                            if useApkSigner:
                                apksign(jarfile, seinfo)
                            else:
                                sign(jarfile, seinfo)
                            recontext(jarfile)
                            break
                        index += 1
                    if index == certlen:
                        print((file + " : Unknown => keeping signature"))

index = 0
for s in itemlist:
    oldsignature = s.attributes['signature'].value
    seinfo = seinfos[index]
    index += 1
    if seinfo in usedseinfos:
        pemtoder = "openssl x509 -outform der -in " + \
            securitydir + "/" + seinfo + ".x509.pem"
        output = subprocess.check_output(['bash', '-c', pemtoder])
        newsignature = output.hex()
        #print (newsignature)
        for mac_permissions_file in mac_permissions:
            for line in fileinput.input(mac_permissions_file, inplace=True):
                print(line.replace(oldsignature, newsignature), end=' ')
