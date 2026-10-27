import os, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

os.chdir(os.path.dirname(os.path.abspath(__file__)))   # immer neben dem Notebook arbeiten
OUT = "cpa_figures"; os.makedirs(OUT, exist_ok=True)

# ---------- shared setup (same as notebook section 7) ----------
MASK = 0xffffffff
CONST = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
d = np.load("chacha20_traces.npz", allow_pickle=True)
T = d["traces"].astype(np.float64); cn = d["ctrnonce"]; KEY = bytes(d["key"].tolist())
N, S = T.shape
in_word = np.array([[int.from_bytes(bytes(cn[i, 4*w:4*w+4].tolist()), "little")
                     for w in range(4)] for i in range(N)], dtype=np.uint64)
kt = [int.from_bytes(KEY[4*j:4*j+4], "little") for j in range(8)]
def hw(v):
    v = np.asarray(v, dtype=np.uint64); c = np.zeros(v.shape, dtype=np.uint64)
    for i in range(32): c += (v >> np.uint64(i)) & np.uint64(1)
    return c.astype(np.float64)
def rotl32(x, n): x = int(x) & MASK; return ((x << n) | (x >> (32 - n))) & MASK
_Tc = T - T.mean(axis=0); _Tden = np.sqrt((_Tc**2).sum(axis=0))
def corr_all(m): m = m - m.mean(); return (m @ _Tc) / (np.sqrt((m**2).sum()) * _Tden + 1e-12)

BLUE, RED, GREEN, ORANGE, GREY = "#1f77b4", "#d62728", "#2ca02c", "#ff7f0e", "#9aa0a6"

# ============ FIG 1: state matrix + attack point ============
fig, ax = plt.subplots(figsize=(8.4, 4.6))
labels = (["const\\n s0","const\\n s1","const\\n s2","const\\n s3"] +
          [f"key\\n s{4+i}" for i in range(8)] +
          ["counter\\n s12","nonce\\n s13","nonce\\n s14","nonce\\n s15"])
cols = (["#dfe6ee"]*4 + ["#f8c9c9"]*8 + ["#cdeccd"] + ["#ffe2bf"]*3)
for idx in range(16):
    r, c = divmod(idx, 4)
    ax.add_patch(Rectangle((c, 3-r), 1, 1, facecolor=cols[idx], edgecolor="white", lw=3))
    ax.text(c+0.5, 3-r+0.5, labels[idx].replace("\\n","\n"), ha="center", va="center", fontsize=9)
# highlight column 0 (attacked) : s0,s4,s8,s12
for idx in (0,4,8,12):
    r,c = divmod(idx,4)
    ax.add_patch(Rectangle((c,3-r),1,1, fill=False, edgecolor=RED, lw=3))
ax.annotate("angegriffene Spalte 0\nQR(0,4,8,12)", xy=(0.5,0.1), xytext=(1.9,-0.75),
            fontsize=10, color=RED, ha="left",
            arrowprops=dict(arrowstyle="->", color=RED))
ax.set_xlim(-0.1,4.1); ax.set_ylim(-1.1,4.1); ax.axis("off")
ax.set_title("ChaCha20-State (16 Wörter) – bekannt / geheim / variierend", fontsize=12)
# legend
from matplotlib.patches import Patch
ax.legend(handles=[Patch(facecolor="#dfe6ee",label="Konstante (bekannt)"),
                   Patch(facecolor="#f8c9c9",label="Key (geheim, fix)"),
                   Patch(facecolor="#cdeccd",label="Counter (bekannt, variiert)"),
                   Patch(facecolor="#ffe2bf",label="Nonce (bekannt, variiert)")],
          loc="lower center", ncol=2, fontsize=8.5, frameon=False, bbox_to_anchor=(0.5,-0.28))
plt.tight_layout(); plt.savefig(f"{OUT}/fig1_state.png", dpi=130, bbox_inches="tight"); plt.close()

# ============ FIG 2: PoI correlation trace, all 4 columns Op2 ============
poi_op2 = []
plt.figure(figsize=(11, 4))
for j, col in enumerate([BLUE, GREEN, ORANGE, RED]):
    dw = in_word[:, j]; W = (CONST[j] + kt[j]) & MASK
    c = corr_all(hw(dw ^ np.uint64(W)))
    p = int(np.argmax(np.abs(c))); poi_op2.append(p)
    plt.plot(np.abs(c), lw=0.8, color=col, label=f"Spalte {j}: s[{4+j}] @ {p} (|r|={abs(c[p]):.2f})")
    plt.scatter([p], [abs(c[p])], color=col, zorder=5, s=25)
plt.xlabel("Sample (Zeit)"); plt.ylabel("|Korrelation|")
plt.title("Op 2 (XOR): korrektes Voll-Wort-Modell – Leckage-Peaks der 1. Runde")
plt.legend(fontsize=8.5); plt.grid(alpha=0.25); plt.tight_layout()
plt.savefig(f"{OUT}/fig2_poi.png", dpi=130); plt.close()

# ============ FIG 3: bit-sign principle (col0 Op2) ============
j = 0; dw = in_word[:, j]; poi = poi_op2[0]; W = (CONST[j] + kt[j]) & MASK
alpha = np.sign(corr_all(hw(dw ^ np.uint64(W)))[poi])
bitcorr = np.array([corr_all(((dw >> np.uint64(i)) & np.uint64(1)).astype(float))[poi] for i in range(32)])
recbits = (np.sign(bitcorr) != alpha).astype(int)
truebits = [(W >> i) & 1 for i in range(32)]
plt.figure(figsize=(12, 4))
colors = [RED if b else BLUE for b in recbits]
plt.bar(range(32), bitcorr, color=colors, edgecolor="white")
plt.axhline(0, color="black", lw=0.8)
plt.xlabel("Bit-Index i von  W = (const + s[4])"); plt.ylabel("corr(trace[PoI], bit_i(d))")
plt.title("Op 2 Bit-Vorzeichen-Recovery, Spalte 0  —  "
          f"Vorzeichen(α)={int(alpha):+d}:  gleich→W_i=0 (blau), entgegengesetzt→W_i=1 (rot)")
# mark any mismatch
for i in range(32):
    if recbits[i] != truebits[i]:
        plt.scatter([i], [bitcorr[i]], marker="x", color="black", zorder=6)
wrong = int(np.sum(recbits != np.array(truebits)))
plt.text(0.5, 0.95, f"Fehlbits: {wrong}/32", transform=plt.gca().transAxes,
         ha="left", va="top", fontsize=10, bbox=dict(boxstyle="round", fc="#eef"))
plt.grid(alpha=0.25, axis="y"); plt.tight_layout()
plt.savefig(f"{OUT}/fig3_bitsign.png", dpi=130); plt.close()

# ============ FIG 4: convergence XOR vs ADD ============
Ns = np.unique(np.linspace(100, N, 15).astype(int))
dw = in_word[:, 0]; W0 = (CONST[0] + kt[0]) & MASK
d2 = np.array([rotl32(int(dw[i]) ^ W0, 16) for i in range(N)], dtype=np.uint64)
H2 = hw(dw ^ np.uint64(W0)); H3 = hw((d2 + np.uint64(kt[4])) & np.uint64(MASK))
# locate Op3 poi
poi3 = int(np.argmax(np.abs(corr_all(H3))))
def r_at(H, t, n):
    h = H[:n]-H[:n].mean(); tt = T[:n,t]-T[:n,t].mean()
    return abs((h@tt)/(np.sqrt((h**2).sum())*np.sqrt((tt**2).sum())+1e-12))
r2 = [r_at(H2, poi_op2[0], n) for n in Ns]; r3 = [r_at(H3, poi3, n) for n in Ns]
plt.figure(figsize=(10, 4))
plt.plot(Ns, r2, "o-", color=BLUE, label="Op 2 (XOR, oberes Key-Wort)")
plt.plot(Ns, r3, "s-", color=RED, label="Op 3 (ADD, unteres Key-Wort)")
plt.axhline(3/np.sqrt(N), color=GREY, ls=":", label=f"Rausch-Schwelle ~3/√N @N={N}")
plt.xlabel("Anzahl Traces N"); plt.ylabel("|r| am PoI (Spalte 0)")
plt.title("Konvergenz: XOR-Stufe leakt deutlich stärker als die ADD-Stufe")
plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
plt.savefig(f"{OUT}/fig4_convergence.png", dpi=130); plt.close()

# ============ FIG 5: recovered-key byte map ============
# run the actual key-free recovery
def recover_xor(dw, poi, alpha):
    W = 0
    for i in range(32):
        if np.sign(corr_all(((dw>>np.uint64(i))&np.uint64(1)).astype(float))[poi]) != alpha: W |= 1<<i
    return W
def recover_add(b, poi, alpha):
    a=0; carry=np.zeros(N,dtype=np.uint64)
    for i in range(32):
        bi=(b>>np.uint64(i))&np.uint64(1); ki=(bi^carry).astype(float)
        ai=1 if np.sign(corr_all(ki)[poi])!=alpha else 0; a|=ai<<i
        av=np.uint64(ai); carry=((av&bi)|(av&carry)|(bi&carry)).astype(np.uint64)
    return a
kw=[0]*8; poi_op3=[]
for j in range(4):
    dw=in_word[:,j]; a2=np.sign(corr_all(hw(dw^np.uint64((CONST[j]+kt[j])&MASK)))[poi_op2[j]])
    kw[j]=(recover_xor(dw,poi_op2[j],a2)-CONST[j])&MASK
    Wj=(CONST[j]+kw[j])&MASK; dd=np.array([rotl32(int(dw[i])^Wj,16) for i in range(N)],dtype=np.uint64)
    p3=int(np.argmax(np.abs(corr_all(hw((dd+np.uint64(kt[4+j]))&np.uint64(MASK)))))); poi_op3.append(p3)
    a3=np.sign(corr_all(hw((dd+np.uint64(kt[4+j]))&np.uint64(MASK)))[p3])
    kw[4+j]=recover_add(dd,p3,a3)
rec_key=b"".join(int(kw[j]).to_bytes(4,"little") for j in range(8))
correct=np.array([rec_key[i]==KEY[i] for i in range(32)]).reshape(2,16)
fig,ax=plt.subplots(figsize=(11,2.6))
ax.imshow(correct, cmap=matplotlib.colors.ListedColormap([RED,GREEN]), vmin=0, vmax=1, aspect="auto")
for r in range(2):
    for cI in range(16):
        ax.text(cI, r, f"{rec_key[r*16+cI]:02x}", ha="center", va="center",
                color="white", fontsize=8, fontweight="bold")
ax.set_xticks(range(16)); ax.set_yticks([0,1]); ax.set_yticklabels(["obere 16 B\n(XOR-Stufe)","untere 16 B\n(ADD-Stufe)"])
ax.set_xlabel("Key-Byte-Index"); ax.set_title(f"Rekonstruierter Schlüssel: {int(correct.sum())}/32 Bytes korrekt "
             f"(grün=richtig, rot=falsch)")
plt.tight_layout(); plt.savefig(f"{OUT}/fig5_keymap.png", dpi=130); plt.close()

print("figures written to", os.path.abspath(OUT))
print("poi_op2",poi_op2,"poi_op3",poi_op3)
print("upper bytes",int(correct[0].sum()),"/16  lower",int(correct[1].sum()),"/16")
