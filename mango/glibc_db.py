GLIBC_STACK_LAYOUTS = {
    "2.35": {
        "main_ret_offset_base": 4,
        "vuln_ret_offset_base": 10,
        "notes": "Ubuntu 22.04 default"
    },
    
    "2.31": {
        "main_ret_offset_base": 6,
        "vuln_ret_offset_base": 10,
        "notes": "Ubuntu 20.04 default"
    },
    
    "2.27": {
        "main_ret_offset_base": 6,
        "vuln_ret_offset_base": 10,
        "notes": "Ubuntu 18.04 default"
    },
    
    "2.39": {
        "main_ret_offset_base": 6,
        "vuln_ret_offset_base": 10,
        "notes": "Newer GLIBC versions (2.39+)"
    },
    
    "default": {
        "main_ret_offset_base": 6,
        "vuln_ret_offset_base": 10,
        "notes": "Default conservative estimate"
    }
}


def get_glibc_layout(version_string):
    if not version_string:
        return GLIBC_STACK_LAYOUTS["default"]
    
    parts = version_string.split('-')[0].split('.')
    if len(parts) >= 2:
        major_minor = f"{parts[0]}.{parts[1]}"
        
        if major_minor in GLIBC_STACK_LAYOUTS:
            return GLIBC_STACK_LAYOUTS[major_minor]
        
        try:
            version_num = float(major_minor)
            closest = None
            closest_diff = float('inf')
            
            for ver_key in GLIBC_STACK_LAYOUTS.keys():
                if ver_key == "default":
                    continue
                try:
                    ver_num = float(ver_key)
                    diff = abs(ver_num - version_num)
                    if diff < closest_diff:
                        closest_diff = diff
                        closest = ver_key
                except ValueError:
                    continue
            
            if closest:
                return GLIBC_STACK_LAYOUTS[closest]
        except ValueError:
            pass
    
    return GLIBC_STACK_LAYOUTS["default"]


def get_local_glibc_version():
    import subprocess
    try:
        result = subprocess.run(
            ['ldd', '--version'],
            capture_output=True,
            text=True,
            timeout=2
        )
        first_line = result.stdout.split('\n')[0]
        if 'libc' in first_line.lower():
            parts = first_line.split()
            for part in parts:
                if part[0].isdigit() and '.' in part:
                    return part.strip(')')
    except Exception:
        pass
    
    return None
