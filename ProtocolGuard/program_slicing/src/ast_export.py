"""Export clang AST JSON to the legacy .cf_<stem>.json format, without a Clang plugin."""
import argparse
import json
import subprocess
from pathlib import Path


def export(source, flags):
    source = Path(source).resolve()
    tree = json.loads(subprocess.check_output(['clang-18', '-Xclang', '-ast-dump=json', '-fsyntax-only', str(source), *flags]))
    text = source.read_text()
    def line(loc):
        loc = loc.get('expansionLoc', loc)
        return loc.get('line', text.count('\n', 0, loc.get('offset', 0)) + 1)
    def span(node):
        r = node.get('range', {})
        return {'start':line(r.get('begin', {})), 'end':line(r.get('end', {}))}
    functions = []
    def walk(node):
        if node.get('kind') == 'FunctionDecl':
            body = next((n for n in node.get('inner',[]) if n.get('kind')=='CompoundStmt'), None)
            if body:
                controls = []
                labels = []
                types={'IfStmt':'IF','ForStmt':'FOR','WhileStmt':'WHILE','DoStmt':'WHILE','SwitchStmt':'SWITCH'}
                def collect_kind(n, kind):
                    result=[line(n.get('range',{}).get('begin',{}))] if n.get('kind')==kind else []
                    for c in n.get('inner',[]): result.extend(collect_kind(c,kind))
                    return result
                def control(n, depth=0):
                    if n.get('kind')=='LabelStmt':
                        labels.append({'name':n.get('name',''), 'range':span(n)})
                    if n.get('kind') in types:
                        children=[c for c in n.get('inner',[]) if c.get('kind')]
                        if not children: return
                        has_else=n.get('hasElse',False)
                        body_node=children[-2] if n['kind']=='IfStmt' and has_else else children[-1]
                        # For loops have init/condition/increment components; retain
                        # the complete header range rather than mislabel its init.
                        condition=span(children[0])
                        if n['kind']=='ForStmt': condition={'start':span(n)['start'],'end':span(body_node)['start']}
                        if n['kind']=='DoStmt':body_node,condition=children[0],span(children[-1])
                        location={'full':span(n),'condition':condition,'body':span(body_node)}
                        if has_else:location['else']=span(children[-1])
                        item={'type':types[n['kind']], 'depth':depth,'children':[], 'location':location}
                        if n['kind']=='SwitchStmt':
                            item['case_lines']=collect_kind(n,'CaseStmt')
                            item['break_lines']=collect_kind(n,'BreakStmt')
                            defaults=collect_kind(n,'DefaultStmt');item['default_line']=defaults[0] if defaults else -1
                        controls.append(item)
                        depth+=1
                    for c in n.get('inner',[]): control(c,depth)
                control(body)
                functions.append({'name':node['name'], 'overall':span(node), 'body':span(body), 'control_flow':controls, 'labels':labels})
        for c in node.get('inner',[]): walk(c)
    walk(tree)
    out = source.with_name('.cf_' + source.stem + '.json')
    out.write_text(json.dumps({'functions':functions},indent=2))
    return out

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('flags',nargs='*')
    a=p.parse_args();print(export(a.source,a.flags))
