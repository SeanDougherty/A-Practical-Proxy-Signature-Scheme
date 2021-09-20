##################
# # # Import # # #
##################
from charm.toolbox.integergroup import IntegerGroupQ
from charm.core.engine.protocol import *
import time
import sys

######################
# # # Parameters # # #
######################
PRIME_SIZE = 1024
msg_file_path = "./res/message.txt"
warrant_file_path = "./res/client.crt"
debug = False


#########################
# # # General Setup # # # 
#######################i##
def setup():

    # Generate a cryptographic "group" for Zq* based signature (see schnorr signature scheme)
    group = IntegerGroupQ(0)

    # Generate p and q with a sufficiently large prime size
    group.paramgen(PRIME_SIZE)

    # Generate keys (private: u, public: e) and generator  
    p = group.p
    u, g = group.random(), group.randomGen()            # u is in Zq, g is in G
    e = (g**u) % p                                      # e is in G, (aka p)
    priv = {'g': g, 'u': u}
    pub = {'g': g, 'e': e}
    
    # read in message warrant
    m_w = open(warrant_file_path, 'r').read()

    # read in message to send
    m_p = open(msg_file_path, 'r').read()

    return {'group': group, 'public': pub,'private': priv,'warrant': m_w, 'message': m_p}

####################################
# # # Proxy Unprotected Scheme # # #
####################################

def generate(m_w, priv, group):
    
    #unpack variables
    p = group.p
    q = group.q
    u = priv['u']
    g = priv['g']

    # start timer
    start = time.perf_counter()

    # select a random integer in Zq, call it i. This behaves somewhat like a private key.
    i = group.random()

    # create a variable t_one, set it equal to i's "public key"
    t_one = (g**i) % p

    # create a hash of the message warrant and t_one, this acts as a nonce
    j = group.hash(m_w, t_one)

    # combine j and the original private key (u) with i, this is now your proxy private key
    b = (j*u + i) % q

    # stop timer
    gen_time = time.perf_counter() - start

    # package up all necessary information
    gener_msg = (m_w, b, t_one, i)

    # end of generate()
    return gener_msg, str(gen_time)


def sign_schnorr(msg, priv, group):
    k = group.random()                      # randomly chosen in Zq
    r = (priv['g'] ** k) % group.p          # evaluated in G, (aka p)
    e = group.hash(msg, r)                  # evaluated in Zq
    s = (k - priv['u'] * e) % group.q       # evaluated in Zq
    return {'s':s, 'e':e}


def sign(gener_msg, msg, priv, pub, group):

    # unpack message
    m_w = gener_msg[0]
    b = gener_msg[1]
    t_one = gener_msg[2]
    i = gener_msg[3]
    p = group.p
    q = group.q
    u = priv['u']
    g = priv['g']
    e = pub['e']

    # start timer
    start = time.perf_counter()

    # create a hash of the message warrant and t_one, this acts as a nonce
    j = group.hash(m_w, t_one)

    # combine j and the original private key (u) with i, this is now your proxy private key
    #b = (j*u + i) % q

    # raise g^b  for verification
    #g_b = (g**b) % p

    # create the check to confirm validity of b and {m_w, t_one} congruence
    #g_b_sign = ( (e**j) * t_one ) % p

    # Verify that g_b and g_b_sign equate
    
    #if debug:
    #    if (g_b != g_b_sign):
    #        print("[Error] g_b and g_b_sign are not equivalent.")
    #    else:    
    #        print("[Success] g^b and e^j * t_one are equivalent.")

    # sign
    sig = sign_schnorr(msg, {'g': g, 'u':b}, group)

    # stop timer
    sign_time = time.perf_counter() - start

    # pass a tuple containing (m_p, s, t_one, m_w) to the verifier
    sign_msg = (msg, sig, t_one, m_w)

    return sign_msg, str(sign_time) 


def verif_schnorr(msg, sig, pub, group):
    r = ((pub['g'] ** sig['s']) * (pub['e'] ** sig['e']))  % group.p    # evaluated in G, (aka p)
    e = group.hash(msg, r)                                              # evaluated in Zq
    if e == sig['e']:
        return True
    else:
        return False
    return None


def verify(sign_msg, pub, group):

    # unpack message
    m_w = sign_msg[3]
    t_one = sign_msg[2]
    sig = sign_msg[1]
    msg = sign_msg[0]
    e = pub['e']
    g = pub['g']
    p = group.p
    q = group.q

    # start timer
    start = time.perf_counter()

    # create a hash of the message warrant and t_one, this acts as a nonce
    j = group.hash(m_w, t_one)

    # raise e to the power of j and multiply by t_one to create the public key
    e_prime = ( (e**j) * t_one ) % p

    # verify
    res = verif_schnorr(msg, sig, {'g': g, 'e': e_prime}, group)

    # stop timer
    verif_timer = time.perf_counter() - start

    if debug:
        if res:
            print("Success")
        else:
            print("Failure")

    return str(verif_timer)



def schnorr_wrapper(vals):
    start1 = time.perf_counter()
    sig = sign_schnorr(vals['message'], vals['private'], vals['group'])
    schnorr_sign_time = time.perf_counter() - start1
    start2 = time.perf_counter()
    verif_schnorr(vals['message'], sig, vals['public'], vals['group'])
    schnorr_verif_time = time.perf_counter() - start2
    return str(schnorr_sign_time), str(schnorr_verif_time)

def master():
    vals = setup()        
    gen_msg, gen_time = generate(vals['warrant'],vals['private'],vals['group'])
    sign_msg, sign_time = sign(gen_msg, vals['message'], vals['private'], vals['public'], vals['group'])
    verif_time = verify(sign_msg, vals['public'], vals['group'])
    schnorr_sign_time, schnorr_verif_time = schnorr_wrapper(vals)

    if debug:
        print('gen_time')
        print(gen_time)
        print('')
        print('sign_time')
        print(sign_time)
        print('')
        print('verif_time')
        print(verif_time)
        print('')
        print('schnorr_sign_time')
        print(schnorr_sign_time)
        print('')
        print('schnorr_verify_time')
        print(schnorr_verif_time)
        print('')

    with open("proxy-signature-timings.csv" , "a") as f:
        f.write((", ".join([gen_time, sign_time, verif_time, schnorr_sign_time, schnorr_verif_time]))+"\n")



master()
