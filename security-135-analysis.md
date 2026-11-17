# FAT 取证恢复的来源偏差与误归因分析（任务 135）

## 1. 背景与调查范围

FAT12/16/32 与 exFAT 的已删除文件恢复在本代码库中有**两条相互独立的内容来源**：

1. **目录项来源（name/meta 层）**：从仍被目录结构引用的目录项中解析出已删除条目（首字节 `0xE5`），路径为
   `fatfs_dir_open_meta`（`tsk/fs/fatfs_dent.cpp:227`）→ `fatxxfs_dent_parse_buf`（`tsk/fs/fatxxfs_dent.c`）/ exFAT 对应解析器。
2. **残留簇来源（雕刻/inode walk 层）**：在未分配簇中扫描"看起来像目录项"的 32 字节结构，路径为
   `fatfs_inode_walk`（`tsk/fs/fatfs_meta.c:1105`），孤儿文件归集由 `tsk_fs_dir_find_orphans`（`tsk/fs/fs_dir.c:1355`）完成。

同一被删除条目可能只被其中一条路径发现，且两条路径的**校验强度、分配状态判定、内容重建方式均不同**，因此"来源偏差"会直接改变已移除条目的证据可信度。以下按来源选择、时间条件、误归因边界三部分展开。

## 2. 来源选择如何影响恢复结果

### 2.1 目录扇区位图决定了"哪里值得看"

`fatfs_inode_walk` 在非孤儿模式下先用 `tsk_fs_dir_walk(ALLOC|RECURSE|NOORPHAN)` 建立 `dir_sectors_bitmap`（`fatfs_meta.c:1241-1282`），随后：

- **已分配但不在位图中的簇被整体跳过**（`fatfs_meta.c:1400-1403`）。代码注释自认："This will miss orphan file entries in the slack space of files"（`fatfs_meta.c:1396-1398`）。即：已删除目录项若残留在**已分配文件簇的 slack** 中，永远不会被 inode walk 发现。
- 未分配簇总是被扫描；位图命中的目录扇区也扫描。FAT12/16 根目录区在孤儿模式下被整体跳过（`fatfs_meta.c:1346-1351`）。

### 2.2 同一条目在不同来源下接受不同的校验强度

`fatfs_inode_walk` 用 `do_basic_dentry_test` 区分校验等级（`fatfs_meta.c:1434-1437`）：

- 已知目录扇区（位图命中且簇已分配）→ **宽松校验**（basic test）；
- 未分配簇 / 非目录扇区 → **严格校验**（in-depth test），包括 8.3 名字符集（`FATXXFS_IS_83_NAME_STRICT`）、属性位、以及全部时间字段合法性（`fatxxfs_meta.c:196-269`）。

`fatxxfs_is_dentry` 中 `strict = (a_do_basic_tests_only == 0)`（`fatxxfs_meta.c:176`）。结果是：**同一段字节，经目录路径被发现则被接受，经残留簇雕刻被发现则可能被拒绝**（反之，宽松路径也接受更多垃圾）。目录行走路径 `fatxxfs_dent_parse_buf` 还有自己的折中：前 4 个条目全部无效才切换为逐条严格测试（`fatxxfs_dent.c:149-157`），意味着损坏目录的前若干条目享受宽松待遇。

`fatxxfs_inode_lookup`（`fatxxfs_meta.c:745`）和 `exfatfs_inode_lookup`（`exfatfs_meta.c:1653`）只用扇区分配状态选择校验等级，注释明确承认"the test here is less reliable and may result in some false positives"。

### 2.3 分配状态是"两级归因"，簇状态优先于删除标记

- FATXX：`fatxxfs_dinode_copy`（`fatxxfs_meta.c:388-398`）与 `fatxxfs_inode_walk_should_skip_dentry`（`fatxxfs_meta.c:860-870`）——簇已分配时才看 `0xE5` 删除标记；**簇未分配时一律判 UNALLOC，无论条目本身是否带删除标记**。目录行走层同样如此（`fatxxfs_dent.c:410-419`，注释："Deleted directories do not always clear the flags of each entry"）。
- exFAT：`exfatfs_inode_walk_should_skip_dentry`（`exfatfs_meta.c:1835-1840`）与 `exfatfs_copy_file_inode`（`exfatfs_meta.c:1211-1227`）——簇分配状态 + 条目类型字节的 in-use 位做 "belt and suspenders" 与运算；簇未分配时 in-use 位为 1 也判 UNALLOC。
- 删除标记本身还随子类型变化：`FATXXFS_IS_DELETED` 在 `TSK_FATFS_SUBTYPE_ANDROID_1` 下改用 `name[0]==0 && name[1]==0`（`tsk_fatxxfs.h:40-43`），同一镜像在不同 subtype 判定下删除结论不同。

### 2.4 内容重建：已删除文件不走 FAT 链，改用连续性猜测

`fatfs_make_data_runs` 对 `TSK_FS_META_FLAG_UNALLOC` 文件进入恢复模式（`fatfs_meta.c:546-735`）：

- 从目录项记录的起始簇开始**顺序向后取未分配簇**，跳过已分配簇，拼满 `fs_meta->size` 为止（`fatfs_meta.c:620-683`）。这隐含"删除前文件连续存放"的假设。
- 若起始簇已被再分配，`canRecover=0`，**回退为只读起始簇一个簇的 run，但属性里仍声明原文件完整大小**（`fatfs_meta.c:709-732`）——icat 读出的第一个簇实际是当前占用者（可能是无关的活文件）的数据，却冠以已删除文件的名字和大小。
- exFAT 的 `NoFatChain` 标志只在**已分配**文件上被遵守（`exfatfs_meta.c:1220-1223`）；已删除 exFAT 文件同样落入上述连续性猜测。

### 2.5 孤儿归集依赖"名字可达性"快照

孤儿 = UNALLOC 且不在 `list_inum_named` 中（`fatxxfs_meta.c:879-883`、`fs_dir.c:1355-1409`）。该名单由 `tsk_fs_dir_load_inum_named` 以 `UNALLOC|RECURSE|NOORPHAN` 做一次目录行走生成（`fs_dir.c:1168-1170`）。因此一个已删除条目是否被归入孤儿目录，取决于它所在的已删除父目录此刻是否还能被遍历到——父目录簇被再分配后，同一条目会从"有路径的已删除文件"退化为"孤儿"，证据语境（原始路径）随之丢失。

## 3. 时间条件如何影响恢复结果

### 3.1 时间合法性是雕刻路径的准入门槛（且只卡雕刻路径）

严格模式下 `fatxxfs_is_dentry` 逐项校验 `ctime/wtime/cdate/adate/wdate`：非零则必须过 `FATFS_ISTIME`/`FATFS_ISDATE`（`tsk_fatfs.h:133-157`），且 `fatfs_dos_2_unix_time(...) != 0`，`ctimeten > 200` 直接拒绝（`fatxxfs_meta.c:227-268`）。这些检查**只在未分配/非目录来源上执行**，造成 2.2 节所述的来源不对称：时间字段轻微越界的真实已删除条目，在目录路径下被保留，在残留簇路径下被丢弃。

exFAT 侧对应门槛是"所有时间戳全零即拒绝"（`exfatfs_meta.c:495-509`）——在时钟未设置的设备上合法创建的文件（时间戳全 0）对雕刻完全不可见。

### 3.2 时间戳换算依赖分析机器的本地时区

`fatfs_dos_2_unix_time` 用 `mktime()` 且 `tm_isdst = -1`（`fatfs_utils.c:178-182`），即把 DOS 时间当作**分析机器本地时间**解释。同一镜像在 `TZ=UTC` 与 `TZ=UTC+8` 的机器上跑 `istat`，同一已删除条目会得到不同的 unix 时间戳，且夏令时切换日附近结果随运行日期漂移。对取证证据而言，这破坏了可复现性：来源相同、时间条件（运行环境）不同，报告的时间线就不同。

### 3.3 时间解析失败被静默吞掉

- `fatfs_dos_2_unix_time` 把 `date==0`、`mktime` 失败、年份被钳制（`tm_year > 137` 即 2107 年后被置 0，`fatfs_utils.c:174-176`）**全部归一为返回 0**。调用方无法区分"条目本就没有时间"与"时间无法解析"。
- `fatxxfs_dinode_copy`（`fatxxfs_meta.c:427-456`）与 `exfatfs_copy_file_inode`（`exfatfs_meta.c:1152-1190`）在 `FATFS_ISDATE` 失败时静默把 mtime/atime/crtime 置 0，不置任何损坏标志——下游看到"时间为 0"无法判断是原始如此还是解析失败。
- FAT 本身无删除时间；crtime 粒度 10ms、atime 仅日期（1 天）、ctime 恒为 0（`fatxxfs_meta.c:459`）。基于时间对已删除条目做排序/关联本身就建立在这些粗粒度字段上。

## 4. 误归因的具体边界

以下每条都是可构造复现的边界条件：

| # | 边界 | 位置 | 误归因表现 |
|---|------|------|-----------|
| B1 | 起始簇已被再分配 | `fatfs_meta.c:612-618, 709-732` | 回退 run 读出**当前占用者的一个簇**，却以已删除文件的名义和完整大小呈现；无任何标志告知调用方内容来自活文件 |
| B2 | 删除前文件非连续 | `fatfs_meta.c:643-683` | 跳过已分配簇后拼接的是**后续任意未分配簇**（可能属于其他已删除文件），内容被拼接污染，无置信度标记 |
| B3 | FAT32 删除时起始簇高 16 位被清零（Windows 行为） | `fatxxfs_meta.c:618-625` 直接采用 `FATXXFS_DENTRY_CLUST` | 起始簇指向错误的低地址簇，恢复出的内容整个张冠李戴，代码无检测 |
| B4 | 已分配文件簇 slack 中的残留目录项 | `fatfs_meta.c:1400-1403` | 该来源被整体跳过，已删除条目**漏报**（假阴性边界） |
| B5 | 未分配簇中无 `0xE5` 标记的条目 | `fatxxfs_meta.c:388-398, 860-870` | 簇状态盖过条目状态：从未经 FS 删除的残留结构（如整体移动过的目录）被报告为"已删除文件" |
| B6 | 已删除父目录的簇被再分配 | `fs_dir.c:1168-1170` + `fatxxfs_meta.c:879-883` | 条目从"有路径"退化为孤儿，路径证据丢失；反之若名单未刷新则分类相反 |
| B7 | LFN 校验和未与 8.3 条目核对 | `fatxxfs_dent.c:166-203` | LFN 校验和只用于检测新序列，**从不与随后的短名条目验证**；中间条目被覆盖时，A 文件的长名会挂到 B 文件的短名条目上 |
| B8 | 运行环境时区不同 | `fatfs_utils.c:178-182` | 同一证据文件的时间戳在不同分析机器上不一致 |
| B9 | 年份 > 2107 或 mktime 失败 | `fatfs_utils.c:174-176, 184-195` | 雕刻路径下整条目被拒（`fatxxfs_meta.c:239-247`），目录路径下时间静默为 0——同一异常时间两种处理 |
| B10 | exFAT 簇未分配但 in-use 位仍为 1（部分写入） | `exfatfs_meta.c:1835-1840` | 簇状态胜出判 UNALLOC；与 FATXX 的 B5 对称，方向相反的部分更新场景无区分处理 |

## 5. 修复建议（不依赖外部服务）

按优先级排列，均可在本仓库内完成：

1. **给恢复内容加来源/置信度标记**（针对 B1、B2）：在 `fatfs_make_data_runs` 的恢复分支中，当 `canRecover==0` 或发生过"跳过已分配簇"时，在 `TSK_FS_ATTR` 上设置一个恢复启发式标志（或复用现有 flag 空间新增 `TSK_FS_ATTR_FLAG_RECOVERY_HEURISTIC`），并在 `istat` 输出中明示。`canRecover==0` 的回退分支应改为返回空 run + `TSK_ERR_FS_RECOVER`，而不是把再分配簇的内容当作已删除文件内容提供（`fatfs_meta.c:709-732`）。
2. **LFN 与短名条目做校验和核对**（针对 B7）：在 `fatxxfs_dent_parse_buf` 拼完 LFN、遇到短名条目时，按 FAT 规范计算短名 11 字节的校验和并与 `lfninfo.chk` 比较，不匹配则丢弃长名只用短名。
3. **消除时区依赖**（针对 B8）：用固定的 civil-date→epoch 换算（如 Howard Hinnant 的 days-from-civil 算法，纯整数、无外部依赖）替换 `fatfs_dos_2_unix_time` 中的 `mktime`，使 DOS 时间一律按 UTC 解释；`tm_isdst` 问题随之消失。
4. **区分"无时间"与"时间解析失败"**（针对 B9 及 3.3）：`fatfs_dos_2_unix_time` 增加出参或返回哨兵区分两种情形；`dinode_copy` 在解析失败时置一个元数据损坏标志而非静默写 0。
5. **统一两条来源的校验强度或记录来源**（针对 2.2、B4-B6）：至少在 `TSK_FS_NAME`/meta 中记录条目是"目录行走发现"还是"未分配簇雕刻发现"，让下游（如 Autopsy）能按来源加权；长期可考虑对已分配非目录簇的 slack 做可选扫描，消除 B4 假阴性。
6. **FAT32 高 16 位清零检测**（针对 B3）：对 FAT32 已删除条目，若 `highclust==0` 且 `startclust` 指向的簇内容不像文件头，输出警告级日志提示恢复可信度低。

## 6. 测试建议（全部本地、无外部服务）

在 `unit_tests/`（现有 C++ 测试框架）或 `tests/` 下新增用例，镜像用代码程序化生成（直接按 FAT 布局写字节，或用仓库已有样例派生），不需要网络：

1. **B1 回归**：构造 FAT32 镜像 → 写入文件 A → 删除 A → 写入文件 B 复用 A 的起始簇 → 断言对已删除 A 的 inode 做 `icat` 不返回 B 的字节（修复前会返回，作为已知失败用例先行记录）。
2. **B2 拼接检测**：构造碎片化已删除文件，中间簇被活文件占用 → 断言恢复内容带启发式标志（配合修复 1）。
3. **时区可复现性**（针对 B8）：同一镜像分别在 `TZ=UTC` 与 `TZ=Pacific/Kiritimati`（UTC+14，含跨日界）下跑 `istat`，断言输出的 unix 时间戳完全一致。修复前此用例应失败，可作为修复 3 的验收。
4. **来源不对称**（针对 2.2）：同一 32 字节条目（含 `ctimeten=255` 或越界月份）分别放入已分配目录簇与未分配簇 → 断言两条路径的接受/拒绝行为符合文档化预期；修复 5 落地后断言行为收敛。
5. **LFN 张冠李戴**（针对 B7）：长名条目 + 短名条目之间覆盖掉一个条目 → 断言长名不再挂到不匹配的短名上（配合修复 2）。
6. **exFAT 全零时间戳**（针对 3.1）：构造时间戳全零的已删除 exFAT 文件条目集 → 断言雕刻路径的可见性行为被明确记录（当前为不可见）。
7. **年份边界**：`wdate` 年份字段取 127（2107 年）与 0（1980 年）的条目各一 → 断言 `istat` 行为确定且一致（配合修复 4）。

运行方式：沿用 `tests/runtests.sh` 与 `unit_tests` 的既有 make 目标，新增用例注册进对应 `Makefile.am` 即可，全程离线。

## 7. 结论

当前实现中，已删除 FAT 条目的"是否被发现、被判为已删除、恢复出什么内容、时间戳是多少"四个维度都随来源路径（目录项 vs 残留簇）与运行环境（时区）而变化。最危险的误归因是 B1/B2/B3：恢复出的**内容**可能部分或全部属于其他文件，且没有任何标志告知分析人员。建议优先落地第 5 节的修复 1-3，并以第 6 节的离线用例做回归约束。
