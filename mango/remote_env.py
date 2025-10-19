import zipfile
import tempfile
import os
import subprocess
import shutil

class RemoteLibAnalyzer:
    def __init__(self, libs_zip_path):
        self.libs_zip_path = libs_zip_path
        self.temp_dir = None
        self.libc_path = None
        self.ld_path = None
        self.libc_version = None
        
        if libs_zip_path:
            self._extract_libs()
            self._analyze_libs()
    
    def _extract_libs(self):
        self.temp_dir = tempfile.mkdtemp(prefix="mango_libs_")
        
        try:
            with zipfile.ZipFile(self.libs_zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    if 'libc.so' in file or 'libc-' in file:
                        self.libc_path = os.path.join(root, file)
                    elif 'ld-linux' in file or 'ld-' in file:
                        self.ld_path = os.path.join(root, file)
        
        except Exception as e:
            print(f"Warning: Failed to extract libs: {e}")
    
    def _analyze_libs(self):
        if not self.libc_path:
            return
        
        try:
            result = subprocess.run(
                ['strings', self.libc_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            for line in result.stdout.split('\n'):
                if 'GNU C Library' in line or 'GLIBC' in line:
                    parts = line.split()
                    for part in parts:
                        if part[0].isdigit() and '.' in part:
                            self.libc_version = part.strip('()')
                            break
                    if self.libc_version:
                        break
        
        except Exception as e:
            print(f"Warning: Failed to analyze libc: {e}")
    
    def get_info(self):
        info = {
            "has_libs": self.libc_path is not None,
            "libc_version": self.libc_version,
            "libc_path": self.libc_path,
            "ld_path": self.ld_path,
        }
        return info
    
    def cleanup(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def __del__(self):
        self.cleanup()
