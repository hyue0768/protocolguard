"""Lossless, deterministic source-evidence partitions for bounded text judges."""
import json
import judge_wrapper

LIMIT=95000


def partition(data,instruction):
    config=dict(model='gpt-5.6-sol',reasoning='medium')
    def packet(documents):
        files={d['file'] for d in documents}
        return dict(data,source_context=documents,
                    symbol_index=[s for s in data['symbol_index'] if s['file'] in files],
                    location_partition_scope='partial source search; merge evidence-backed candidates; no global absence conclusion')
    def size(value):
        user='Return a valid json object only.\n\n'+json.dumps(value,ensure_ascii=False,separators=(',',':'))
        return judge_wrapper.prompt_characters(judge_wrapper.payload(config,instruction,user))
    # Preserve whole files when possible; split only oversized files at original
    # numbered source lines. Do not drop or renumber any source evidence.
    pieces=[]
    def split(doc):
        if size(packet([doc]))<=LIMIT:pieces.append(doc);return
        if len(doc['lines'])<2:raise ValueError('One source line plus its symbol index exceeds the Wrapper budget; explicit narrower scope required before any request')
        middle=len(doc['lines'])//2
        split(dict(doc,lines=doc['lines'][:middle]));split(dict(doc,lines=doc['lines'][middle:]))
    for doc in data['source_context']:split(doc)
    batches=[];current=[]
    for doc in pieces:
        if current and size(packet(current+[doc]))>LIMIT:
            batches.append(packet(current));current=[]
        current.append(doc)
    if current or not batches:batches.append(packet(current))
    if any(size(b)>LIMIT for b in batches):raise ValueError('Location fixed context exceeds Wrapper budget; no request sent')
    return batches
