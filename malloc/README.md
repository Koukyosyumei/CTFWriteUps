# Heap Exploit

## Overview of Heap

- stack: 関数内の一時的な領域確保
- mmap: ページ数サイズ単位の領域確保
- heap: 要求に応じた適切なサイズを永続的に確保

heapお重を管理する機構をアロケータと呼び、mallocとfreeというインターフェースを持つ

- malloc: メモリ確保
- heap: 利用済み領域の解放

### Usage and Structure of Heap

カーネルから確保したメモリープルを予め用意しておき、そのプールの一部を切り分けることでヒープは利用される。

プール内において、領域の確保は下位 -> 上位へとおこなわれる。

- malloc: プールの一部を切り出してプログラムにメモリを提供
- free: 不要になった領域をプールに返却

#### メモリプールの確保

ヒープとして利用される領域は、ブレーク値を上位に引き上げることでカーネルから確保される。

- ブレーク値: 仮想アドレス空間に割り当てられた未初期化のデータセグメント末尾のアドレス (データセグメントとは、仮想メモリのデータ用領域のこと)

このブレーク値は、`sys_brk`システムコールで変更することができる。

#### チャンク

ヒープはチャンクと呼ばれるブロック単位で切り分けられて管理されている。

- MINSIZE: 一つのチャンクの最小サイズ (0x20バイト)

```c
struct malloc_chunk{
	INTERNAL_SIZE_T mchunk_prev_size; // size of previous chanks (if free)
	INTERNAL_SIZE_T mchink_size       // size in bytes, including overheaf

	struct malloc_chunk* fd; // double links -- used only if free.
	struct malloc_chunk* bk;

	// only used for large blocks: pointer to next large size.
	struct malloc_chunk* fd_nextsize; // double links -- used only if free.
	struct malloc_chunk* bk_nextsize;
};
```

チャンクのサイズは0x10バイト単位にアライメントされているので、下位4ビットは常に0になる。そこで、sizeの下位3ビットに以下のフラグを埋め込む。

- P: PREV_INUSE - prev_chunkが利用中の際にセットされる
- M: IS_MMAPED - ヒープ領域ではなく、mmapによって確保された領域上にある際にセットされる。
- A: NON_MAIN_ARENA - main_arenaではない別のアリーナで管理されている

#### アリーナ

メモリープールはアリーナと呼ばれる機構で管理されている。

```c
struct malloc_state
{
	mfastbiptr fastbinsY[NFASTBINS]; // fastbinをサイズ別に管理する単方向の線形リストの配列

	mchunkptr top; // メモリプールの未使用領域の先頭
	mchunkptr last_reminder; // 既存の解法済みチャンクを分割した際、利用されなかった残りのチャンク1つ

	mchunkptr bins[NBINS * 2 - 2]; // unsortedbin、smallbin、largebinを管理する双方向の循環リストの配列
	unsigned int binmap[BINMAPSIZE]; // チャンクがつながっているbinsのインデックスに対応するフラグが立つマップ

	INTERNAL_SIZE_T system_mem; システムから確保したメモリプールの総量
};
```


