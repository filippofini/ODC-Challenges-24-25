# The secret code was in stack_check_fail
# The goal was to find the hashed flag in md5 that was equal to each value of musk_tweet in memory 
# At first i tried using libdebug but it didn't work on my mac
# My idea was to try every char like we did in class with provola (I used teh same code), checking if the 
# return value of strcmp was 0.
# after failing, I just wrote a md5 generator in python and check with the hashed values in memory 
# (see below)
"""
from libdebug import debugger
import string

found = False
flag = b"$"*65
new_flag = flag
def check_cmp(t, bp):
    if(t.regs.eax == 0):
        found = True


d = debugger("./tweet", continue_to_binary_entrypoint=False) #continue_to_binary_entrypoint=False


for i in range(65):
    found = False
    for c in string.printable:

        new_flag = flag[:i] + c.encode() + flag[i+1:]

        r = d.run()

        bp = d.bp(0x135F, file="tweet", callback=check_cmp) #hardware=True

        d.cont()

        r.recvuntil(b'Insert your tweet: ')
        r.sendline(new_flag)

        d.wait()
        d.kill()

        if found == True:
            flag = new_flag
            print(new_flag)
            break

print(c, bp.hit_count)
"""

import hashlib
import string

values = [
    "8fa14cdd754f91cc6554c9e71929cce7", "3d296788f2a7e19ffbd912521d94a5f4", "61894b21be75260c4964065b1eecec4d",
    "327a6c4304ad5938eaf0efb6cc3e53dc", "4ff89342bb46cea91a288c3bed86e1b2", "ac94a1654d789865c592fd40935990dc",
    "672bc009d5ffeccc52a2fd5eaa8fd6aa", "950302f09d6e3c0462e626583227ec67", "e242e70497108fedf48aa07a01f332b2",
    "5c6d2457a8ce3231bf9dda896b81bc1a", "3feb60a1cb67b5ccb887b125e531887f", "9128aae6b9da27fcc3227becea5b4a2e",
    "5ae6db14a1b509b3d12741198dcedbc9", "a6bce35d63c4bd67cb8fa9830d01bad8", "d1aaabc6978046329f4999fee2a3f0b4",
    "0b8dd393016d4519cb4294fde77c1185", "f0eca6657eff9ea2a87b2e47ac9ba838", "b38a3177324fb8e3f8d4622bb8a97485",
    "f5e19f475ea357346af3b33f15985c29", "4f24093d8889ade0725fbe883d73d5ac", "ec4c4d46a2a92d3ba201b66406939b69",
    "acf50e0e841e83b9fed835e74e1ca652", "9301adbb367a8da14c2cda90c38206de", "49097d028e70b167a2bfd2ba4fb5fa4d",
    "0467be53cf7f4aaf896e84b9313212ea", "205bd2d6e403059a78511c4b478938b6", "e7b533820592100fdbbc346af2ace2ed",
    "3d8766d82a027afc965446381ae28754", "de2443e42c48f80ce7373a5019314bf4", "44b825f66117a1ab8e4e2f92c08c0548",
    "098fb2675c5c1430a4b61677ce5cc996", "189b301b623134ffc2e797aff241e445", "5b85151187846c566e3644eccf0b5788",
    "9558846ed12638320cfd211382903339", "a73428cc4614ccb9497ae0017f5f5804", "647dc92c37f6fc1fa9e18b493176ceba",
    "a128898b5c45c4cd1302a0c182faf74f", "273e30454718d6fc3d53b899a2a77826", "c83472de5b5b785e4026ad96c89ac149",
    "612e3fd95ae5a319bbfedc59bf61d908", "33bf3f20c1b107cf045b847b84aaedc8", "21dd763ae114a0ea525b9fc2910f21e8",
    "6ae21644cea8f93231a0bb6410b9417d", "b2d3e6fb1230e379ff7ba7879b795260", "2a39946f9dedb31d2f70b8c8ee8f4b2d",
    "9eae34ce0d900c47f5bbeaacfebd597a", "07db849545a326172918a0eacbc5e8f2", "5208aa5124c772d3347d344f184f3e1e",
    "dce79f517ef06354a7f6eab884392337", "c773710116e21563f5de88764b8b68af", "e5f08ef626b7a33b4e4012fde0aabe4c",
    "57255f106e14e55d0925d023c2fd5abe", "88342014a5b5d9f3adc714c84099141f", "7515b4ab5884eafc27a8c220848d9291",
    "c76d67d7be8b620a0656e76e40823a7e", "5b8fb256c2fdff391b8afa4a85c4c388", "4939d0e30fd73903771e884fbdcc7d44",
    "48b0b611cfa40caeff74697a26a80915", "862a2fb7709470850acfff2e6d151966", "bade73ae58b4fe4e01b69270c86a970b",
    "5ffba1a81324ceeed07452de80bdb25d", "0a5cc045772b4b9e07901a967c207756", "1de0ed8c8d727d3b5f4807c84b5dbea3",
    "76d58a8ea2596e95bf1a7d2783edf42b", "16443a1490f7d9a1d9cb61f2ebadb72f", "3ceb12f5f458d12231c2bef5fd111f6c"
]


def do_md5(flag):
    md5 = hashlib.md5()
    
    md5.update(flag.encode())
    return md5.hexdigest()

flag = ""
for i in range(66):
    for c in string.printable:
        hash_md5 = do_md5(flag + c)
        if hash_md5 == values[i]:
            flag += c
            break
print(flag)