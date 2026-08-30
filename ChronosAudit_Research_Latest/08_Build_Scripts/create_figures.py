from pathlib import Path
import json
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import cairosvg

ROOT=Path('/mnt/data/ChronosAudit_Stage2A_2E_Execution')
FIG=ROOT/'figures'; FIG.mkdir(exist_ok=True)
ART=ROOT/'artifact'
a=json.loads((ART/'reports/stage2a_2e_audit.json').read_text())
k=pd.read_csv(ART/'reports/killer_question_fix_loop.csv')

ACCENT='#174f6b'; LIGHT='#e9f0f4'; MID='#90a8b5'; DARK='#17313f'; WARN='#8a5b22'; BLOCK='#f4ece2'

def save(fig, name):
    fig.savefig(FIG/f'{name}.png', dpi=320, bbox_inches='tight')
    fig.savefig(FIG/f'{name}.pdf', bbox_inches='tight')
    fig.savefig(FIG/f'{name}.svg', bbox_inches='tight')
    plt.close(fig)

# Figure 1 pipeline
fig, ax=plt.subplots(figsize=(12,4.2)); ax.set_xlim(0,12); ax.set_ylim(0,4.2); ax.axis('off')
labels=[('2A','Temporal + provenance','0 certified'),('2B','Code + proxy identity','408 identities'),('2C','Protocol + mechanism','50 seed labels'),('2D','Controls + censoring','0 controls'),('2E','Leakage + release','0 released')]
xs=[0.3,2.65,5.0,7.35,9.7]
for i,(stage,title,result) in enumerate(labels):
    box=FancyBboxPatch((xs[i],1.35),1.95,1.45,boxstyle='round,pad=0.04,rounding_size=0.08',facecolor=LIGHT,edgecolor=ACCENT,linewidth=1.5)
    ax.add_patch(box); ax.text(xs[i]+.975,2.47,stage,ha='center',va='center',fontsize=13,fontweight='bold',color=ACCENT)
    ax.text(xs[i]+.975,2.05,title,ha='center',va='center',fontsize=9,color=DARK)
    ax.text(xs[i]+.975,1.62,result,ha='center',va='center',fontsize=9,fontweight='bold',color=WARN)
    if i<4:
        ax.add_patch(FancyArrowPatch((xs[i]+1.97,2.08),(xs[i+1]-.08,2.08),arrowstyle='-|>',mutation_scale=15,linewidth=1.3,color=MID))
ax.text(6,3.65,'ChronosAudit Stage 2A-2E evidence qualification pipeline',ha='center',fontsize=16,fontweight='bold',color=DARK)
ax.text(6,.72,'Mandatory evidence missing at any stage -> reason-coded exclusion -> no benchmark release',ha='center',fontsize=11,color=DARK)
ax.add_patch(FancyBboxPatch((3.8,.25),4.4,.65,boxstyle='round,pad=.03',facecolor=BLOCK,edgecolor=WARN,linewidth=1.2))
ax.text(6,.575,'FAIL-CLOSED DECISION: IMPLEMENTED WORKFLOW, EVIDENCE GATES BLOCKED',ha='center',va='center',fontsize=10,fontweight='bold',color=WARN)
save(fig,'figure_1_stage2_pipeline')

# Figure 2 data planes
fig,ax=plt.subplots(figsize=(10.5,5)); ax.set_xlim(0,10.5); ax.set_ylim(0,5); ax.axis('off')
for x,title,items,fc in [(.4,'Detector-admissible plane',['code/state available at cutoff','deployment-time metadata','frozen retrieval corpus','no incident explanations'],LIGHT),(5.55,'Evaluator-only plane',['later incident outcome','protocol/mechanism adjudication','attacker-family attribution','censoring and follow-up'],BLOCK)]:
    ax.add_patch(FancyBboxPatch((x,.8),4.55,3.35,boxstyle='round,pad=.05',facecolor=fc,edgecolor=ACCENT if x<1 else WARN,linewidth=1.6))
    ax.text(x+2.275,3.75,title,ha='center',fontsize=14,fontweight='bold',color=DARK)
    for j,item in enumerate(items):
        ax.text(x+.35,3.15-.58*j,u'• '+item,fontsize=10.5,color=DARK)
ax.add_patch(FancyArrowPatch((4.95,2.5),(5.5,2.5),arrowstyle='|-|',mutation_scale=18,linewidth=2,color=WARN))
ax.text(5.23,2.86,'access boundary',ha='center',fontsize=9,color=WARN)
ax.text(5.25,.35,'Evaluator-only information may audit contamination but must never enter model inputs, prompts, tools, or retrieval.',ha='center',fontsize=10.5,fontweight='bold',color=DARK)
save(fig,'figure_2_information_planes')

# Figure 3 killer question loop
fig,ax=plt.subplots(figsize=(10.5,4.8)); ax.set_xlim(0,10.5); ax.set_ylim(0,4.8); ax.axis('off')
steps=[('1','Ask adversarial question'),('2','Measure current evidence'),('3','Apply automatable control'),('4','Re-run verification'),('5','Pass or external blocker')]
coords=[(1.0,2.5),(3.0,3.6),(5.5,3.6),(7.8,2.5),(5.5,1.15)]
for (n,t),(x,y) in zip(steps,coords):
    ax.add_patch(FancyBboxPatch((x-.85,y-.42),1.7,.84,boxstyle='round,pad=.03',facecolor=LIGHT,edgecolor=ACCENT,linewidth=1.4))
    ax.text(x,y+.13,n,ha='center',fontsize=12,fontweight='bold',color=ACCENT)
    ax.text(x,y-.16,t,ha='center',fontsize=8.5,color=DARK,wrap=True)
for a1,a2 in zip(coords,coords[1:]):
    ax.add_patch(FancyArrowPatch(a1,a2,arrowstyle='-|>',mutation_scale=13,color=MID,linewidth=1.2,connectionstyle='arc3,rad=0.05'))
ax.add_patch(FancyArrowPatch(coords[-1],coords[0],arrowstyle='-|>',mutation_scale=13,color=WARN,linewidth=1.2,connectionstyle='arc3,rad=-0.35'))
ax.text(5.25,4.48,'Closed-loop killer-question audit',ha='center',fontsize=16,fontweight='bold',color=DARK)
ax.text(5.25,.35,'100 questions: 19 executed PASS, 36 design-resolved, 3 partial, 42 externally blocked',ha='center',fontsize=10.5,color=DARK)
save(fig,'figure_3_killer_loop')

# Figure 4 leakage result
fig,ax=plt.subplots(figsize=(8.5,4.6))
labels=['Row-random\n5-fold','Exact-identity\ngrouped']
vals=[100,0]
bars=ax.bar(labels,vals,color=[WARN,ACCENT],width=.55)
ax.set_ylabel('Assignments with identity leakage (%)')
ax.set_ylim(0,110); ax.grid(axis='y',alpha=.25)
ax.set_title('Exact-identity leakage under alternative partitioning',fontweight='bold')
for bar,v in zip(bars,vals): ax.text(bar.get_x()+bar.get_width()/2,v+3,f'{v}%',ha='center',fontweight='bold')
ax.text(.0,93,'1,000 / 1,000 simulations\nmean 7.227 crossing groups',ha='center',va='top',fontsize=9)
ax.text(1,8,'0 crossings\nfolds: 84/84/83/83/83',ha='center',va='bottom',fontsize=9)
for side in ['top','right']: ax.spines[side].set_visible(False)
save(fig,'figure_4_leakage_result')

# Figure 5 stage audit statuses
pivot=k.groupby(['stage','final_status']).size().unstack(fill_value=0).reindex(['2A','2B','2C','2D','2E'])
order=['PASS','PASS_BY_DESIGN','PARTIAL','BLOCKED']
fig,ax=plt.subplots(figsize=(9,4.8))
bottom=[0]*len(pivot)
colors={'PASS':ACCENT,'PASS_BY_DESIGN':MID,'PARTIAL':'#d5b26b','BLOCKED':'#a96645'}
for status in order:
    vals=pivot.get(status,pd.Series(0,index=pivot.index)).values
    ax.bar(pivot.index,vals,bottom=bottom,label=status.replace('_',' ').title(),color=colors[status])
    bottom=[a+b for a,b in zip(bottom,vals)]
ax.set_ylim(0,21); ax.set_ylabel('Killer questions (20 per stage)'); ax.set_xlabel('Stage')
ax.set_title('Stage-specific closure status after the fix loop',fontweight='bold')
ax.legend(ncol=4,loc='upper center',bbox_to_anchor=(.5,-.14),frameon=False)
ax.grid(axis='y',alpha=.2)
for side in ['top','right']: ax.spines[side].set_visible(False)
save(fig,'figure_5_stage_status')
print('figures created', list(FIG.glob('*')))
