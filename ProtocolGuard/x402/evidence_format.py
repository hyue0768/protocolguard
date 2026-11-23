"""Auditable quote-format repair; never changes identifiers, lines or claims."""
from copy import deepcopy
import hashlib
import json


def documents(value):
    result=[]
    for key in ['norms','source_context']:
        items=value.get(key,[])
        if isinstance(items,list):result.extend(items)
    if isinstance(value.get('document'),dict):result.append(value['document'])
    if isinstance(value.get('slice'),dict):result.extend(value['slice'].get('code',[]))
    return result


def normalize(value,docs):
    allowed={(d['file'],l['line']):l['text'] for d in docs for l in d.get('lines',[])}
    result=deepcopy(value);changes=[]
    def walk(item):
        if isinstance(item,dict):
            evidence=item.get('evidence')
            if isinstance(evidence,list):
                for e in evidence:
                    if not isinstance(e,dict) or not isinstance(e.get('file'),str) or type(e.get('line')) is not int or not isinstance(e.get('quote'),str):continue
                    original=e['quote'];actual=allowed.get((e['file'],e['line']))
                    if not actual or original in actual:continue
                    prefix='';candidate=original
                    while candidate.startswith('\\t'):
                        prefix+='\t';candidate=candidate[2:]
                    if prefix and prefix+candidate in actual:
                        corrected=prefix+candidate
                        changes.append(dict(file=e['file'],line=e['line'],original_quote=original,corrected_quote=corrected,
                                            kind='leading_tab_escape_quote_format_only'))
                        e['quote']=corrected
                        continue
                    quote=original.strip();source=actual.strip()
                    # Only a complete same-line quote differing in the final
                    # comma/semicolon is repairable. No whitespace relaxation,
                    # fuzzy match, invented locations or identifier replacement.
                    if (len(quote)>1 and len(source)>1 and quote[:-1]==source[:-1]
                            and {quote[-1],source[-1]}=={',',';'}):
                        changes.append(dict(file=e['file'],line=e['line'],original_quote=original,corrected_quote=actual,
                                            kind='terminal_comma_semicolon_quote_format_only'))
                        e['quote']=actual
            for key,child in list(item.items()):
                if key!='local_evidence_corrections':walk(child)
        elif isinstance(item,list):
            for child in item:walk(child)
    walk(result)
    if changes:
        result['local_evidence_corrections']=changes
        result['original_model_value_sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    return result
