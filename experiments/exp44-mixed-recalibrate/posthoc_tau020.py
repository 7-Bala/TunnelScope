# POST-HOC, not pre-registered: what the tau=0.20 candidate (one session short of the bar) would do. For the owner's information only.
import importlib.util, json, sys, numpy as np
from pathlib import Path
ROOT=Path("/Users/bala/Documents/SIH 2026"); sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/"build/models"))
import corpus, featurize, features_v2
from tunnelscope.leakage import attacker as A, mixed as MX
from sklearn.ensemble import RandomForestClassifier
spec=importlib.util.spec_from_file_location("e44",ROOT/"experiments/exp44-mixed-recalibrate/analyze.py"); e44=importlib.util.module_from_spec(spec); spec.loader.exec_module(e44)
spec=importlib.util.spec_from_file_location("e43",ROOT/"experiments/exp43-lab-d/analyze.py"); e43=importlib.util.module_from_spec(spec); spec.loader.exec_module(e43)
# rebuild the rows exactly as the scorer did (same code path), then save a tau=0.20 candidate
ss=corpus.load(); data=e44.E42.Data("v2",ss,aug=True); ok=[i for i,w in enumerate(data.w) if len(w)>=3]
mux=e44.mux_sessions(); mw=featurize.windows(mux,"v2"); F=[];L=[]
for fam in corpus.FAMILIES:
    te=[i for i in ok if ss[i].family==fam]
    if not te: continue
    m=e44.fit_k4(data,[i for i in ok if ss[i].family!=fam])
    F+=[MX.session_features(m.predict_proba(data.w[i])) for i in te]; L+=["single"]*len(te)
    if fam=="lab-tgen":
        for s,w in zip(mux,mw):
            if len(w)>=3: F.append(MX.session_features(m.predict_proba(w))); L.append("mixed")
p=Path("/tmp/mx_tau020.npz"); np.savez_compressed(p,X=np.array(F),y=np.array(L),tau=np.array(0.20))
def run(datafile):
    MX.DATA=str(datafile); MX._model.cache_clear()
    ans=right=0
    for d in e43.lab_d():
        r=A.assess_exposure([{"t":float(t),"src":"o" if o else "i","ip_len":int(n)} for t,o,n in zip(d["t"],d["out"],d["size"])],"o")
        if r["status"]=="measured" and r["traffic"]["answered"]: ans+=1; right+=int(r["traffic"]["class"]==d["label"])
    mx=sum(1 for s in mux if s.sid.startswith("EXP-05") and not (lambda r: r["status"]=="measured" and r["traffic"]["answered"])(A.assess_exposure([{"t":float(t),"src":"o" if o else "i","ip_len":int(n)} for t,o,n in zip(s.t,s.out,s.size)],"o")))
    return {"lab_d_answered":ans,"lab_d_correct":right,"exp05_mixed_not_answered":mx,"exp05_n":sum(1 for s in mux if s.sid.startswith("EXP-05"))}
print(json.dumps({"current_detector":run(ROOT/"tunnelscope/models/mixed_windows.npz"),"tau_0.20_candidate":run(p)},indent=1))
