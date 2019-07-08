PCStat - Program Context based I/O Profiler
=======================================

Program Context 단위로 응용의 I/O를 분석하는 프로파일러이자,
이를 활용한 최적화 방안을 함께 제시합니다.

파일 설명
--------------

# linux/ : 커널에 삽입될 코드가 저장되어 있습니다.
각 폴더는 리눅스 커널 내의 디렉토리를 의미합니다.
각 폴더 내의 파일은 해당 디렉토리에서 새로 추가했거나 수정한 파일을 가지고 있습니다.
linux/pc.c : PC system call 의 구현입니다.

# pc/ : 별도로 삽입될 I/O 및 PC 수집을 위한 커널 모듈입니다.
kernel_file_io.c, kernel_file_io_h : 커널 모듈이 로그 파일을 남기기 위해 사용하는 I/O API 구현입니다.
pcmain.c : I/O 및 PC 수집을 하기 위한 모듈의 구현입니다.

# analyzer/ : I/O 기록을 분석하는 PCStat의 구현입니다.
pcstat.py : PCStat의 구현입니다.
pcstat_loader.sh : PCStat을 실행합니다. 실행법은 파일을 참고해주시기 바랍니다.
유의) pcstat.py 을 실행하기 전 'logs' 폴더를 만들어두시는 것이 좋습니다.

# optimizer/ : PCStat을 통한 정보를 기반으로 최적화를 자동화하는 PCAdvisor의 구현입니다.
pcadvisor.c : PCAdvisor 커널 모듈의 구현입니다.

사용 방법 설명
-------------

PCStat 은 세 가지 과정을 거칩니다.

# 1. 응용 수행 도중 I/O 정보 수집

pc/ 의 커널 모듈을 삽입하여 응용 수행 도중에 system call 발생 시 I/O 정보를 수집합니다.

# 2. PCStat을 통한 분석

1을 통해 생성된 로그 파일과 바이너리 정보를 활용하여 분석합니다.
적용하고자 하는 최적화의 형태에 따라 output 의 형식을 바꿀 수 있습니다.

# 3. 최적화 적용
PCStat의 분석 기록을 바탕으로 두 가지 방식의 최적화를 적용할 수 있습니다.

## 1. 코드 수정
PCStat은 수집한 PC를 실제 함수명으로 변환하여,
어느 코드라인에서 어떤 I/O가 발생하는지 알 수 있습니다.
사용자에게 보여주는 함수명을 바탕으로, 코드 내에 fadvise 등을 적용하여 수정합니다.

## 2. PCAdvisor 활용
PCAdvisor 전용 모드로 PCStat을 통해 분석한 뒤,
PCAdvisor 모듈을 삽입하므로서 I/O 최적화를 자동화할 수 있습니다.
