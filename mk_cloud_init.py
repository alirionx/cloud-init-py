#!/usr/bin/python3

#-Draft Version: Ubuntu 18.04 + only-

#---Admins should change values only in this area-------------------------
#-General---
PackUpdate = False
VmId = "my-cloud-vm-1"
IsoFileName = "ci_"+VmId+".iso"

#-User---
UserName = "ubuntu"
PassWord = "ubuntu"
SshPubKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXp0D0tDZRNxlGcUN/tpVbt7BZCVmdXjJYUbj+BVLc65tjf8gNEY3vCv/gFecW1807TipRnkQ9TGFLXDN7BZ06lXX5VUNS7AFiXY+iGAvJsGLWy6+VLbyBMlNeK+vFQ0GKnQDa7nrVF84uh8Oh6bQ7Jgbtx8HOIDv6Pp4RIDK5X/BWUOfWpeSipXnk1k0c6kv0Hz3B8XzbutgA5YYNabOLIryMMf+07ntCB6dg55nNgItjiw9ogG3EcEshEDJI4T1K4d5EIHc75CxPjGjDLiEjzclsGjldtSTbB+SG7qM4ZTeEb5OSL+Pm225z5xy7AbOVUqEofysKMYNhEpePkY7F"
SuDo = True

#-Network---
HostName = "mytestvm2"
NetConfPath = "/etc/netplan/50-cloud-init.yaml"
NetDevName = "ens18"
IpV4Cidr = "192.168.10.201/24"
IpV4Gateway = "192.168.10.1"
IpV4NameServers = ["192.168.10.1", "192.168.10.20"]


#-------------------------------------------------------------------------


#---Global Vars-----------------------------------------------------------
import os


scriptDirPath = os.path.dirname(os.path.realpath(__file__))
confFilesDirName = 'conf-files'
confFilesDirPath = os.path.join(scriptDirPath, confFilesDirName)
#print(confFilesDirPath)

NeededPyMods = {
  "posix": {
    "yaml": "via apt: python3-yaml",
    #"base64": False,
    "crypt": False, 
  },
  "nt": {
    "yaml": "via pip: PyYaml",
    "bcrypt": "via pip: bcrypt", 
  }
}
myNeededPyMods = NeededPyMods[os.name]

isoBins = {
  "posix": "genisoimage",
  "nt": os.path.join(scriptDirPath, "bin", "mkisofs.exe")
}
NeededExecs = {
  "posix": [
    {
      "name": "genisoimage", 
      "test": [isoBins["posix"], "-help"],
      "info": "sudo apt install genisoimage"
    }
  ],
  "nt": [
    {
      "name": "mkisofs", 
      "test": [isoBins["nt"], "-help"],
      "info": "can be downloaded at https://sourceforge.net/projects/mkisofs-md5/"
    }
  ]
}
myNeededExecs = NeededExecs[os.name]


MetaDataObj = {
  "instance-id": VmId
}

UserDataObj = {
  "hostname": HostName,
  "manage_etc_hosts": True,
  "users": [
    {
      "name": UserName,
      "shell": "/bin/bash",
      "lock_passwd": False,
      "ssh_pwauth": True,
      "ssh-authorized-keys": [ SshPubKey ]
    }
  ],
  "write_files": [
    {
      "path": NetConfPath,
      "permissions": '0644',
    }
  ],
  "runcmd": [
    'sudo netplan apply'
  ]
}

#---System Check----------------------------------------------------------
import sys
import subprocess
import importlib

notInstalled = []

for mod in myNeededPyMods:
  try:
    importlib.import_module(mod) 
  except:
    notInstalled.append(mod)

if len(notInstalled) > 0:
  print("The following python packages are required:")
  for mod in notInstalled:
    print(" - " + mod + " => " + str(myNeededPyMods[mod]))
  exit()

notInstalled = []
devnull = open(os.devnull, 'wb')
i = 0
for exe in myNeededExecs:
  #res = os.system(exe["test"])
  #if res != 0:
  #  notInstalled.append(i)
  
  cmd = exe["test"]
  try:
    subprocess.check_call(cmd, stdout=devnull, stderr=subprocess.STDOUT)
  except:
    notInstalled.append(i)

  i += 1

if len(notInstalled) > 0:
  print("The following system tools are required:")
  for i in notInstalled:
    print(" - " + myNeededExecs[i]["name"] + " => via: " + myNeededExecs[i]["info"])
  exit()

if not os.path.isdir(confFilesDirPath):
  os.mkdir(confFilesDirPath)

#-import the rest-----
import yaml

#---Build the meta-data file----------------------------------------------

yamlStr = yaml.dump(MetaDataObj)
tgtPath = os.path.join(confFilesDirPath, "meta-data")
yamlFileObj = open(tgtPath, "w")
yamlFileObj.write(yamlStr)
yamlFileObj.close()

#---Build the user-data file----------------------------------------------

if PackUpdate:
  UserDataObj["package_upgrade"] = True

if SuDo:
  UserDataObj["users"][0]["sudo"] = "ALL=(ALL) NOPASSWD:ALL"


if os.name == "posix":
  import crypt
  passwdHash = crypt.crypt(PassWord)
elif os.name == "nt":
  import bcrypt
  passwd = bytes(PassWord, encoding='utf-8')
  salt = bcrypt.gensalt()
  passwdHash = bcrypt.hashpw(passwd, salt).decode('utf-8')
  print(passwdHash)
else:
  exit("something went wrong while importing crypto tools...")

UserDataObj["users"][0]["passwd"] = passwdHash
#UserDataObj["users"][0]["passwd"] = '$5$S1Nrzlns$T97UG2IZKenTnzm.VywtTVCZ2mlm8kAAEdfPl7g7.ZD'

#-NICHT GUT!!!! -> Das geht besser!!! -> to be continue
UserDataObj["write_files"][0]["content"] = "${PLACEHOLDER}"
yamlStr = "#cloud-config\n" + yaml.dump(UserDataObj, default_style=None)

netConfStr = '''|
    network:
      version: 2
      ethernets:
        '''+NetDevName+''':
          addresses: 
            - '''+IpV4Cidr+'''
          gateway4: '''+IpV4Gateway+'''
          nameservers:
            addresses: ['''+', '.join(IpV4NameServers)+''']
'''
yamlStr = yamlStr.replace('${PLACEHOLDER}', netConfStr)
#-------------------------------------------------------

tgtPath = os.path.join(confFilesDirPath, "user-data")
yamlFileObj = open(tgtPath, "w")
yamlFileObj.write(yamlStr)
yamlFileObj.close()

#---Build the iso file----------------------------------------------------

try: 
  subprocess.call([isoBins[os.name], "-JR", "-V", "CIDATA", "-o", IsoFileName, confFilesDirPath+"/"])
except:
  print("something went wrong while creating the iso file...")

#-------------------------------------------------------------------------