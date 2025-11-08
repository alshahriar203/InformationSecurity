#!/usr/bin/env python3
import random
import math
import time
from collections import Counter
import string
import re
import os

"""
Monoalphabetic substitution solver with hill-climbing + fallback scoring (no quadgrams).

Usage:
 - Edit cipher1/cipher2 or load from files, then run.
"""

# -------------------------
# Config / Cipher texts
# -------------------------
cipher1 = """af p xpkcaqvnpk pfg, af ipqe qpri, gauwiikfc tpw, ceiri udvk tiki afgaxifrphni cd eao-
wvmd popkwn, hiqpvri du ear jvaql vfgikrcpf gafm du cei xkafqaxnir du xrwqedeardckw pfg
du ear aopmafp casing xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm
epexxifig cd ringdf eaorin hiudki cei opceiopcaq r du cei uaing qdvng hi qdoxnicinw tdkli
dvc-pfg edt rndtnw ac xkdqiijig, pfg edt odvfcpa fdvr cei dhrcpqnir--ceiki tdvng pc niprc
kiopaf dfi mddg oafg cepc tdvng qdfcafvi cei kiripkqe"""

cipher2 = """aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu vcdluz lu loj avhqnik aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumi, omj ck toz yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs kqmmuez zkqffuj tckl kwiozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz vyhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok omghmu zlhqej yhzzuzz (oyyovumkeg) yuvyukqoe ghqkl oz tuee oz (vuyqkujeg)
cmublogzkaeeu tuoekl. ck teee lopu kh au yocj shv, klug zocj. ck czm'k mokqvoe, omj kvhqaeu
teee dhwu hs ckl aqk zh sov kvhqaeu loj mhk dhwu; omj oz wv. aonncmz toz numuvhqz tckl
lcz whmug, whzk yuhyeu tuvu teeccmn kh shvncpu lcw lcz hijckcuz omj lcz nhhj shvkgmu. lu
vuwocmuj hm pczckcmn kuwwz tckl lcz vueokcpuz (ubduyk, hs dhqvzu, klu zodrpceeu-
aonncmzuz), omj lu loj womg juphkuj ojwcvuvz owhnm klu lhaackz hs yhhv omj
qmcwyhvkomk sowcecuz. aqk lu loj mh dehzu svcumjz, qmkce zhwu hs lcz ghqmnuv dhqzcmz
aunom kh nvht qy. klu uejuzk hs kluzu, omj aceah'z sophqvcku, toz ghqmn svhjh aonncmz.
tlum aceah toz mcmukg-mcmu lu ojhykuj svhjh oz lcz lucv, omj avhqnik lcw kh ecpu ok aon
umj; omj klu lhyuz hs klu zodrpceeu- aonncmzuz tuvu scmoeeg jozluj. aceah omj svhjh
lovyumuj kh lopu klu zowu acvkijog, zuykuwauv 22mj. ghq loj aukkuv dhwu omj ecpu luvu,
svhjh wg eoj, zocj aceah hmu jog; omj klum tu dom dueuavoku hqv acvkijog-yovkcuz
dhwshvkoaeg khnukluv. ok klok kcwu svhjh toz zkcee cm lcz ktuumz, oz klu lhaackz doeeuj klu
cvvuzyhmzeaeu ktumkcuz auktuum dicejlhhj omj dhwcnnn hs onu ok klcvkg-klvuu"""

# -------------------------
# Utilities / constants
# -------------------------
alphabet = "abcdefghijklmnopqrstuvwxyz"
_word_re = re.compile(r"[a-z]+")
common_words = set([
    "the","and","that","have","for","not","with","you","this","but","from","they","say",
    "her","she","will","one","all","would","there","their","what","so","up","out","if",
    "about","who","get","which","go","me","when","make","can","like","time","no","just",
    "him","know","take","people","into","year","your","good","some","could","them","see",
    "other","than","then","now","look","only","come","its","over","think","also","back",
    "after","use","two","how","our","work","first","well","way","even","new","want","because",
    "any","these","give","day","most","us","in","it","to","of","a"
])
common_digrams = ["th","he","in","er","an","re","ed","on","es","st","en","at","te","or","ti","hi","as","is","et","ng"]

# english single-letter expected frequencies (percent) - used in fallback chi-square
english_freq_pct = {
    'a':8.05,'b':1.67,'c':2.23,'d':5.10,'e':12.22,'f':2.14,'g':2.30,'h':6.62,'i':6.28,'j':0.19,
    'k':0.95,'l':4.08,'m':2.33,'n':6.95,'o':7.63,'p':1.66,'q':0.06,'r':5.29,'s':6.02,'t':9.67,
    'u':2.92,'v':0.82,'w':2.60,'x':0.11,'y':2.04,'z':0.06
}

# fallback English order (frequency)
english_order = "etaoinshrdlucmfwygpbvkxqjz"

# -------------------------
# Mapping helpers
# -------------------------
def frequency_order_letters(text):
    letters = re.sub("[^a-z]", "", text.lower())
    counts = Counter(letters)
    sorted_letters = sorted(alphabet, key=lambda c: counts.get(c,0), reverse=True)
    return sorted_letters, counts

def build_initial_mapping(text):
    sorted_letters, _ = frequency_order_letters(text)
    mapping = {sorted_letters[i]: english_order[i] for i in range(26)}
    return mapping

def apply_mapping(text, mapping):
    out = []
    for ch in text:
        low = ch.lower()
        if 'a' <= low <= 'z':
            out.append(mapping.get(low, '?'))
        else:
            out.append(ch)
    return ''.join(out)

def mapping_to_key(mapping):
    # returns a 26-char key where index 0 = mapping for 'a', etc.
    inv = {k:v for k,v in mapping.items()}
    return ''.join(inv.get(ch, '?') for ch in alphabet)

# -------------------------
# Scoring functions (fallback-only)
# -------------------------
def fallback_score(plaintext):
    t = plaintext.lower()
    words = _word_re.findall(t)
    wc = Counter(words)
    score = 0.0
    # reward whole common words
    for w in common_words:
        if wc.get(w,0):
            score += 3.0 * wc[w]
    # reward 'the' heavily
    score += 8.0 * wc.get("the",0)
    # digrams reward
    letters = ''.join(words)
    if len(letters) > 1:
        dg_counts = Counter(letters[i:i+2] for i in range(len(letters)-1))
        for dg in common_digrams:
            score += 0.6 * dg_counts.get(dg,0)
    # letter frequency chi-square similarity
    total = len(letters)
    if total > 0:
        cnt = Counter(letters)
        chi2 = 0.0
        for ch, exp_pct in english_freq_pct.items():
            exp = exp_pct * total / 100.0
            obs = cnt.get(ch,0)
            if exp > 0:
                chi2 += (obs - exp)**2 / exp
        score += max(0, 40 - chi2) * 0.25
    # penalize many single-letter nonsense tokens
    singles = sum(1 for w in words if len(w)==1 and w not in ('a','i'))
    score -= 0.6 * singles
    return score

# wrapper scoring: fallback only
def score_plaintext(plaintext):
    return fallback_score(plaintext)

# -------------------------
# Random neighbor (swap) generation
# -------------------------
def random_swap_map(mapping):
    # swap plaintext letters assigned to two cipher letters
    keys = list(mapping.keys())
    a, b = random.sample(keys, 2)
    nm = mapping.copy()
    nm[a], nm[b] = mapping[b], mapping[a]
    return nm

# -------------------------
# Hill-climbing + simulated annealing
# -------------------------
def hill_climb(ciphertext, init_map, iterations=2000, temp_start=0.8, temp_end=0.001):
    cur_map = init_map.copy()
    cur_plain = apply_mapping(ciphertext, cur_map)
    cur_score = score_plaintext(cur_plain)
    best_map, best_plain, best_score = cur_map.copy(), cur_plain, cur_score

    for i in range(iterations):
        # exponential temperature schedule
        t = temp_start * ((temp_end/temp_start) ** (i/(iterations-1))) if iterations>1 else temp_end
        cand_map = random_swap_map(cur_map)
        cand_plain = apply_mapping(ciphertext, cand_map)
        cand_score = score_plaintext(cand_plain)
        delta = cand_score - cur_score
        # accept if better or with probability
        if delta > 0 or math.exp(delta / (t + 1e-12)) > random.random():
            cur_map, cur_plain, cur_score = cand_map, cand_plain, cand_score
            if cand_score > best_score:
                best_map, best_plain, best_score = cand_map.copy(), cand_plain, cand_score
    return best_map, best_plain, best_score

# -------------------------
# Multi-restart solve; returns top N unique plaintexts
# -------------------------
def solve(ciphertext, time_limit=25.0, restarts=10, iter_per=1200, top_n=10, seed=0):
    random.seed(seed)
    initial = build_initial_mapping(ciphertext)
    candidates = []
    # include the initial mapping plaintext
    candidates.append((score_plaintext(apply_mapping(ciphertext, initial)), apply_mapping(ciphertext, initial), initial.copy()))
    start_time = time.time()
    for r in range(restarts):
        if time.time() - start_time > time_limit:
            break
        # diversify starting map by performing some random swaps
        start_map = initial.copy()
        for _ in range(3 + (r % 4)):
            start_map = random_swap_map(start_map)
        best_map, best_plain, best_score = hill_climb(ciphertext, start_map, iterations=iter_per)
        candidates.append((best_score, best_plain, best_map.copy()))
        # small local refinements
        for _ in range(2):
            m2,p2,s2 = hill_climb(ciphertext, best_map, iterations=max(200, iter_per//6))
            candidates.append((s2,p2,m2.copy()))

    # deduplicate plaintexts (normalize whitespace)
    uniq = {}
    for sc, pt, m in candidates:
        key = " ".join(pt.split())
        if key not in uniq or sc > uniq[key][0]:
            uniq[key] = (sc, pt, m)
    sorted_list = sorted(uniq.values(), key=lambda x: x[0], reverse=True)[:top_n]
    # return as list of (score, plaintext, mapping-key)
    return [(sc, pt, mapping_to_key(m)) for sc,pt,m in sorted_list]

# -------------------------
# Main runner
# -------------------------
def main():
    print("Running solver using fallback scoring only (no quadgrams).")

    # Solve both ciphers (tweak time_limit/restarts/iter_per for more thorough search)
    print("\nSolving Cipher-1...")
    top1 = solve(cipher1, time_limit=20.0, restarts=8, iter_per=1400, top_n=10, seed=1234)
    for i,(sc,pt,key) in enumerate(top1,1):
        print(f"\n--- Cipher-1 Rank {i} (score {sc:.3f}) ---")
        print("Key (mapping for 'a'..'z'):", key)
        print(pt)

    print("\n" + "="*80 + "\n")
    print("Solving Cipher-2...")
    top2 = solve(cipher2, time_limit=20.0, restarts=8, iter_per=1400, top_n=10, seed=9999)
    for i,(sc,pt,key) in enumerate(top2,1):
        print(f"\n--- Cipher-2 Rank {i} (score {sc:.3f}) ---")
        print("Key (mapping for 'a'..'z'):", key)
        print(pt)

if __name__ == "__main__":
    main()
