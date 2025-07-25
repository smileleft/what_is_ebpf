# 5.2.2 perf tools

- 목표
    - perf를 사용하여 특정 파일작업(파일 생성/쓰기/읽기) 중 발생하는 파일시스템 이벤트를 추적하고 분석한다
- 프로젝트 구조
    - monitor_fs_perf.sh: perf 명령어를 실행하고 파일 작업을 수행하는 스크립트
    - test_file_operations.c: 간단한 파일 생성, 쓰기, 읽기 작업을 수행하는 C 프로그램

```bash
.
├── monitor_fs_perf.sh
└── test_file_operations.c
```

# test_file_operations.c (C 프로그램)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define FILE_NAME "test_file.txt"
#define TEST_DATA "Hello, perf for filesystem monitoring!\n"
#define BUFFER_SIZE 1024

int main() {
    int fd;
    ssize_t bytes_written, bytes_read;
    char buffer[BUFFER_SIZE];

    printf("Starting file operations...\n");

    // 1. 파일 생성 및 열기 (쓰기 모드)
    fd = open(FILE_NAME, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }
    printf("File '%s' created and opened for writing.\n", FILE_NAME);

    // 2. 파일에 데이터 쓰기
    bytes_written = write(fd, TEST_DATA, strlen(TEST_DATA));
    if (bytes_written == -1) {
        perror("Error writing to file");
        close(fd);
        return 1;
    }
    printf("Wrote %zd bytes to '%s'.\n", bytes_written, FILE_NAME);
    close(fd);

    // 3. 파일 열기 (읽기 모드)
    fd = open(FILE_NAME, O_RDONLY);
    if (fd == -1) {
        perror("Error opening file for reading");
        return 1;
    }
    printf("File '%s' opened for reading.\n", FILE_NAME);

    // 4. 파일에서 데이터 읽기
    bytes_read = read(fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read == -1) {
        perror("Error reading from file");
        close(fd);
        return 1;
    }
    buffer[bytes_read] = '\0'; // Null-terminate the buffer
    printf("Read %zd bytes from '%s': '%s'\n", bytes_read, FILE_NAME, buffer);
    close(fd);

    // 5. 파일 삭제
    if (unlink(FILE_NAME) == -1) {
        perror("Error deleting file");
        return 1;
    }
    printf("File '%s' deleted.\n", FILE_NAME);

    printf("File operations completed.\n");

    return 0;
}
```

# monitor_fs_perf.sh

```bash
#!/bin/bash

# C 프로그램 컴파일
echo "Compiling test_file_operations.c..."
gcc test_file_operations.c -o test_file_operations
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi
echo "Compilation successful."

echo "---------------------------------------------------"
echo "Starting perf monitoring for filesystem events..."
echo "---------------------------------------------------"

# perf record를 사용하여 파일시스템 관련 트레이스 포인트 기록
# -e 'syscalls:sys_enter_open' : open 시스템 콜 진입 추적
# -e 'syscalls:sys_exit_open'  : open 시스템 콜 종료 추적
# -e 'syscalls:sys_enter_write' : write 시스템 콜 진입 추적
# -e 'syscalls:sys_exit_write'  : write 시스템 콜 종료 추적
# -e 'syscalls:sys_enter_read' : read 시스템 콜 진입 추적
# -e 'syscalls:sys_exit_read'  : read 시스템 콜 종료 추적
# -e 'syscalls:sys_enter_unlink' : unlink 시스템 콜 진입 추적
# -e 'syscalls:sys_exit_unlink'  : unlink 시스템 콜 종료 추적
# -a : 시스템 전체 추적 (전역적 파일시스템 활동을 보려면 유용)
# --call-graph dwarf : 함수 호출 그래프를 생성 (더 자세한 정보를 위해)
# -o perf.data : 결과를 perf.data 파일에 저장
sudo perf record -e 'syscalls:sys_enter_open,syscalls:sys_exit_open,syscalls:sys_enter_write,syscalls:sys_exit_write,syscalls:sys_enter_read,syscalls:sys_exit_read,syscalls:sys_enter_unlink,syscalls:sys_exit_unlink' \
                 -a --call-graph dwarf -o perf.data \
                 ./test_file_operations

echo "---------------------------------------------------"
echo "perf monitoring completed. Analyzing results..."
echo "---------------------------------------------------"

# perf report를 사용하여 기록된 데이터 분석
# -g : 호출 그래프 표시
sudo perf report -g

echo "---------------------------------------------------"
echo "Done."
echo "---------------------------------------------------"

# 생성된 실행 파일 및 데이터 파일 정리 (선택 사항)
# rm test_file_operations perf.data
```

# 프로젝트 실행

1. 위 파일들 저장
2. monitor_fs_perf.sh 파일에 실행 권한 부여

```bash
chmod 744 monitor_fs_perf.sh
```

1. 스트립트 실행

```bash
./monitor_fs_perf.sh
```

# 결과분석

- [perf.data](http://perf.data) 파일이 생성됨
- perf report 명령어를 통해 터미널에 분석 결과가 출력됨, 출력된 결과는 다음 정보를 포함
    - **Overhead**: 각 이벤트 또는 함수가 전체 시스템 작업에서 차지하는 비율.
    - **Command**: 해당 이벤트가 발생한 프로세스.
    - **Shared Object**: 이벤트가 발생한 공유 라이브러리 또는 실행 파일.
    - **Symbol**: 이벤트가 발생한 함수 또는 커널 심볼.
    - **Callgraph**: `--call-graph` 옵션을 사용했다면, 함수 호출 스택을 보여주어 이벤트가 어떤 코드 경로를 통해 발생했는지 파악할 수 있슴
