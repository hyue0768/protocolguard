"""Text-only local Judge Wrapper transport helpers; no credential-file access."""
import os
import json
from urllib.parse import urlsplit

MAX_PROMPT_CHARACTERS=100000


def prompt_characters(request):
    # Match compatibility.normalize() in the dedicated wrapper. Count the
    # actual nested JSON conversation, not just the HTTP body or user text.
    conversation=[dict(role=m['role'],content=m['content']) for m in request['messages']]
    if request.get('response_format',{}).get('type')=='json_object':
        conversation.insert(0,dict(role='developer',content='Return a valid JSON object, with no markdown fences.'))
    prefix=('Respond to the last user request in this JSON conversation. Respect message roles: '
            'system/developer instructions take precedence over user messages. Return only the assistant response.\n')
    return len(prefix+json.dumps(conversation,ensure_ascii=False))


def configuration():
    base=os.environ.get('PROTOCOLGUARD_JUDGE_BASE_URL','http://127.0.0.1:18768/v1').rstrip('/')
    url=urlsplit(base)
    if (url.scheme!='http' or url.netloc not in ['127.0.0.1:18768','127.0.0.1:18769'] or url.path!='/v1'
            or url.query or url.fragment):
        raise ValueError('Judge Wrapper must use the dedicated ProtocolGuard loopback instance on 18768 or 18769')
    model=os.environ.get('PROTOCOLGUARD_JUDGE_MODEL','gpt-5.6-sol')
    effort=os.environ.get('PROTOCOLGUARD_JUDGE_REASONING_EFFORT','medium')
    if not model or effort not in ['none','minimal','low','medium','high','xhigh']:
        raise ValueError('Invalid Judge Wrapper model/reasoning configuration')
    return dict(endpoint=base+'/chat/completions',model=model,reasoning=effort,timeout=600)


def payload(config,instruction,user_input):
    return dict(model=config['model'],reasoning_effort=config['reasoning'],
                messages=[dict(role='system',content=instruction),dict(role='user',content=user_input)],
                response_format=dict(type='json_object'),max_completion_tokens=12000,
                tools=[],tool_choice='none',stream=False)


def assertion_format():
    evidence={'type':'object','additionalProperties':False,'properties':{
        'file':{'type':'string'},'line':{'type':'integer'},'quote':{'type':'string'}},
        'required':['file','line','quote']}
    assertion={'type':'object','additionalProperties':False,'properties':{
        'id':{'type':'string'},'case_id':{'type':'string'},
        'predicate':{'type':'string','enum':['rejected','roundtrip_equal','observe_only']},
        'justification':{'type':'string'},'assumptions':{'type':'array','items':{'type':'string'}},
        'evidence':{'type':'array','items':evidence}},
        'required':['id','case_id','predicate','justification','assumptions','evidence']}
    return dict(type='json_schema',json_schema=dict(name='protocolguard_assertion_plan',schema={
        'type':'object','additionalProperties':False,'properties':{
            'rule_id':{'type':'string'},
            'adapter_status':{'type':'string','enum':['supported_component_cases','adapter_missing']},
            'assertions':{'type':'array','items':assertion},
            'uncovered_requirements':{'type':'array','items':{'type':'string'}}},
        'required':['rule_id','adapter_status','assertions','uncovered_requirements']}))


def extraction_format(value):
    from extraction_format import LIST_FIELDS
    candidate=value['candidate'];document=value['document']
    properties={k:{'type':'string'} for k in ['obligation','actor','normative_strength']}
    properties['message_type']={'type':['string','null']}
    properties['applicability']={'type':['string','null']}
    for field in LIST_FIELDS:properties[field]={'type':'array','items':{'type':'string'}}
    properties['unspecified_list_fields']={'type':'array','items':{'type':'string','enum':LIST_FIELDS}}
    properties['evidence']={'type':'array','minItems':1,'items':{'type':'object','additionalProperties':False,
        'properties':{'line':{'type':'integer','enum':[l['line'] for l in document['lines']]}},'required':['line']}}
    atom={'type':'object','additionalProperties':False,'properties':properties,'required':list(properties)}
    root={'candidate_id':{'type':'string','enum':[candidate['id']]},
          'classification':{'type':'string','enum':['normative','non_normative','ambiguous']},
          'rules':{'type':'array','maxItems':64 if candidate.get('scope')=='whole_document_model_interpretation_not_exhaustiveness_proof' else 8,'items':atom},
          'limitations':{'type':'array','items':{'type':'string'}},'unprocessed_sections':{'type':'array','items':{'type':'string'}}}
    return dict(type='json_schema',json_schema=dict(name='protocolguard_rule_extraction',schema={
        'type':'object','additionalProperties':False,'properties':root,'required':list(root)}))


def normalized_response(answer):
    if not isinstance(answer,dict) or not isinstance(answer.get('choices'),list) or len(answer['choices'])!=1:
        raise ValueError('Judge Wrapper returned invalid choices; no retry')
    choice=answer['choices'][0]
    if not isinstance(choice,dict) or not isinstance(choice.get('message'),dict):
        raise ValueError('Judge Wrapper returned an invalid message; no retry')
    message=choice['message'];finish=choice.get('finish_reason')
    if message.get('role')!='assistant' or message.get('tool_calls') or message.get('function_call'):
        raise ValueError('Judge Wrapper must return one text assistant message without tools')
    content=[]
    if message.get('refusal'):content.append(dict(type='refusal'))
    text=message.get('content')
    if isinstance(text,str):content.append(dict(type='output_text',text=text))
    status='completed' if finish=='stop' else 'incomplete'
    reason='max_output_tokens' if finish=='length' else 'content_filter' if finish=='content_filter' else 'unknown'
    tokens=answer.get('usage',{});tokens=tokens if isinstance(tokens,dict) else {}
    usage={new:tokens[old] for old,new in [('prompt_tokens','input_tokens'),('completion_tokens','output_tokens'),('total_tokens','total_tokens')]
           if type(tokens.get(old)) is int}
    return dict(status=status,incomplete_details=None if status=='completed' else dict(reason=reason),
                output=[dict(type='message',role='assistant',content=content)],usage=usage)
