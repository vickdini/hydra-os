import os
import re

def audit_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Pre-calculate lines inside trait implementations (impl ... for ...)
    depth = 0
    in_trait = 0
    pending_impl = False
    trait_lines = set()
    for idx, line in enumerate(lines):
        code = line.split('//')[0]
        if pending_impl:
            if '{' in code:
                in_trait = depth + 1
                pending_impl = False
        elif re.search(r'\bimpl\b.*?\bfor\b', code):
            if '{' in code:
                in_trait = depth + 1
            else:
                pending_impl = True
        
        depth += code.count('{') - code.count('}')
        if in_trait > 0:
            trait_lines.add(idx)
            if depth < in_trait:
                in_trait = 0

    issues = []
    i = 0
    in_extern_block = False
    while i < len(lines):
        if i in trait_lines:
            i += 1
            continue

        line = lines[i]
        stripped = line.strip()

        if re.match(r'^(?:pub\s+)?extern\s+(?:"[^"]+"\s+)?\{', stripped):
            in_extern_block = True
            i += 1
            continue

        if in_extern_block:
            if stripped == '}' or stripped.startswith('}'):
                in_extern_block = False
            i += 1
            continue

        # Match function definition
        m = re.match(r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([a-zA-Z0-9_]+)\s*(<[^>]*>)?\s*\((.*?)\)(?:\s*->\s*([^{;]+))?', line)
        if not m:
            # check multiline fn definition header
            m2 = re.match(r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([a-zA-Z0-9_]+)', line)
            if m2 and not line.strip().startswith('//') and not line.strip().startswith('/*'):
                # collect until { or ;
                fn_name = m2.group(1)
                full_sig = line
                k = i
                while k < len(lines) and '{' not in lines[k] and ';' not in lines[k]:
                    k += 1
                    if k < len(lines):
                        full_sig += " " + lines[k].strip()
                # now inspect doc comments preceding line i
                j = i - 1
                doc_lines = []
                while j >= 0:
                    l = lines[j].strip()
                    if l.startswith('///') or l.startswith('#['):
                        if l.startswith('///'):
                            doc_lines.append(l)
                        j -= 1
                    else:
                        break
                doc = "\n".join(doc_lines)
                
                # Check arguments
                # see if arguments exist between ( and )
                args_match = re.search(r'\((.*?)\)', full_sig, re.DOTALL)
                has_params = False
                if args_match:
                    params_str = args_match.group(1).strip()
                    # filter out &self, &mut self, self
                    param_list = [p.strip() for p in params_str.split(',') if p.strip()]
                    non_self_params = [p for p in param_list if p not in ('&self', '&mut self', 'self', 'mut self')]
                    if len(non_self_params) > 0:
                        has_params = True

                has_return = False
                if '->' in full_sig:
                    # check if return type is not ()
                    ret_part = full_sig.split('->')[1].split('{')[0].split(';')[0].strip()
                    if ret_part != '()':
                        has_return = True

                is_unsafe = 'unsafe' in full_sig.split('fn')[0]

                missing = []
                if not doc_lines:
                    missing.append("MISSING_DOC")
                else:
                    if has_params and '# Arguments' not in doc:
                        missing.append("MISSING_ARGS")
                    if has_return and '# Returns' not in doc:
                        missing.append("MISSING_RETURNS")
                    if is_unsafe and '# Safety' not in doc:
                        missing.append("MISSING_SAFETY")

                if missing:
                    issues.append((i + 1, fn_name, missing))
        else:
            fn_name = m.group(1)
            params_str = m.group(3).strip()
            ret_type = m.group(4)
            full_sig = line

            j = i - 1
            doc_lines = []
            while j >= 0:
                l = lines[j].strip()
                if l.startswith('///') or l.startswith('#['):
                    if l.startswith('///'):
                        doc_lines.append(l)
                    j -= 1
                else:
                    break
            doc = "\n".join(doc_lines)

            param_list = [p.strip() for p in params_str.split(',') if p.strip()]
            non_self_params = [p for p in param_list if p not in ('&self', '&mut self', 'self', 'mut self')]
            has_params = len(non_self_params) > 0

            has_return = False
            if ret_type:
                ret_part = ret_type.split('{')[0].split(';')[0].strip()
                if ret_part != '()':
                    has_return = True

            is_unsafe = 'unsafe' in line.split('fn')[0]

            missing = []
            if not doc_lines:
                missing.append("MISSING_DOC")
            else:
                if has_params and '# Arguments' not in doc:
                    missing.append("MISSING_ARGS")
                if has_return and '# Returns' not in doc:
                    missing.append("MISSING_RETURNS")
                if is_unsafe and '# Safety' not in doc:
                    missing.append("MISSING_SAFETY")

            if missing:
                issues.append((i + 1, fn_name, missing))

        i += 1

    return issues

if __name__ == '__main__':
    total_issues = 0
    file_count = 0
    for root, dirs, files in os.walk('src'):
        for file in sorted(files):
            if file.endswith('.rs'):
                path = os.path.join(root, file).replace('\\', '/')
                issues = audit_file(path)
                if issues:
                    file_count += 1
                    total_issues += len(issues)
                    print(f"\n{path} ({len(issues)} issues):")
                    for line_no, fn_name, miss in issues[:10]:
                        print(f"  L{line_no}: fn {fn_name} -> {', '.join(miss)}")
                    if len(issues) > 10:
                        print(f"  ... and {len(issues) - 10} more")
    print(f"\nTotal files with issues: {file_count}, Total function issues: {total_issues}")