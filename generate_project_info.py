import os
from pathlib import Path

def collect_files(base_dir):
    """
    收集指定目录下的 build.gradle.kts 和 Java 文件
    返回文件列表，包含路径和标题
    """
    files_info = []
    
    # 检查并添加 build.gradle.kts
    build_gradle_path = Path(base_dir) / "build.gradle.kts"
    if build_gradle_path.exists():
        files_info.append({
            "path": str(build_gradle_path),
            "title": "build.gradle.kts"
        })
    
    # 检查 /src/main/java/com/vulcheck/ 目录
    vulcheck_dir = Path(base_dir) / "src" / "main" / "java" / "com" / "vulcheck"
    if not vulcheck_dir.exists():
        print(f"错误：目录 {vulcheck_dir} 不存在")
        return files_info
    
    # 添加 Extension.java
    extension_path = vulcheck_dir / "Extension.java"
    if extension_path.exists():
        files_info.append({
            "path": str(extension_path),
            "title": "Extension.java"
        })
    
    # 收集 poc、ui、utils 子目录中的 Java 文件
    subdirs = ["poc", "ui", "utils"]
    for subdir in subdirs:
        subdir_path = vulcheck_dir / subdir
        if subdir_path.exists() and subdir_path.is_dir():
            for java_file in subdir_path.glob("*.java"):
                files_info.append({
                    "path": str(java_file),
                    "title": f"{subdir}/{java_file.name}"
                })
    
    return files_info

def read_file_content(file_path):
    """
    读取文件内容，处理编码问题
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        print(f"警告：无法以 UTF-8 编码读取 {file_path}，尝试其他编码")
        try:
            with open(file_path, 'r', encoding='latin1') as f:
                return f.read()
        except Exception as e:
            print(f"错误：无法读取 {file_path} - {str(e)}")
            return ""

def write_project_info(base_dir, output_file="projectinfo.txt"):
    """
    将目录结构、文件标题和内容写入 projectinfo.txt
    """
    files_info = collect_files(base_dir)
    output_path = Path(base_dir) / output_file
    
    with open(output_path, 'w', encoding='utf-8') as out:
        # 写入目录结构
        out.write("=== 目录结构 ===\n")
        out.write(f"{base_dir}/\n")
        out.write("  build.gradle.kts\n")
        out.write("  src/\n")
        out.write("    main/\n")
        out.write("      java/\n")
        out.write("        com/\n")
        out.write("          vulcheck/\n")
        out.write("            Extension.java\n")
        out.write("            poc/\n")
        for file_info in files_info:
            if file_info['title'].startswith("poc/"):
                out.write(f"              {file_info['title'].split('/')[-1]}\n")
        out.write("            ui/\n")
        for file_info in files_info:
            if file_info['title'].startswith("ui/"):
                out.write(f"              {file_info['title'].split('/')[-1]}\n")
        out.write("            utils/\n")
        for file_info in files_info:
            if file_info['title'].startswith("utils/"):
                out.write(f"              {file_info['title'].split('/')[-1]}\n")
        out.write("\n")
        
        # 写入文件内容
        for file_info in files_info:
            out.write(f"=== 文件: {file_info['title']} ===\n")
            content = read_file_content(file_info['path'])
            out.write(content)
            out.write("\n\n")

def main():
    # 获取当前工作目录
    base_dir = os.getcwd()
    print(f"正在处理目录: {base_dir}")
    
    # 生成 projectinfo.txt
    try:
        write_project_info(base_dir)
        print(f"成功生成 {base_dir}/projectinfo.txt")
    except Exception as e:
        print(f"错误：生成 projectinfo.txt 失败 - {str(e)}")

if __name__ == "__main__":
    main()