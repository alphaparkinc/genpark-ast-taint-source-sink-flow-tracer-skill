from client import AstTaintSourceSinkFlowTracerClient

def main():
    client = AstTaintSourceSinkFlowTracerClient()
    res = client.trace_taint_dataflow()
    print('AST Taint Flow Tracer: ' + res['trace_id'] + ' (' + res['file_path'] + ')')
    print('Vulnerable: ' + str(res['is_vulnerable_unmitigated_flow']) + ' | Risk: ' + res['security_risk_level'])
    print('Trace URL: ' + res['trace_callgraph_url'])

if __name__ == '__main__':
    main()
