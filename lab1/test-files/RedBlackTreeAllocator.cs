using System;
using System.Collections.Generic;
using System.Linq;

namespace AllocatorSample;

public readonly record struct MemoryBlock(int Offset, int Size);
public sealed class RedBlackTreeAllocator
{
    private readonly int _totalSize;
    private readonly SortedSet<FreeBlock> _freeBySize =
        new(FreeBlockSizeComparer.Instance);
    private readonly SortedSet<FreeBlock> _freeByOffset =
        new(FreeBlockOffsetComparer.Instance);
    private readonly Dictionary<int, int> _allocated = [];

    public RedBlackTreeAllocator(int totalSize)
    {
        if (totalSize <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(totalSize),
                "Размер модельной памяти должен быть положительным.");
        }

        _totalSize = totalSize;
        AddFreeBlock(new FreeBlock(Offset: 0, Size: totalSize));
    }

    public int TotalSize => _totalSize;

    public int AvailableMemory => _freeByOffset.Sum(block => block.Size);

    public int LargestFreeBlock =>
        _freeBySize.Count == 0 ? 0 : _freeBySize.Max.Size;


    public MemoryBlock Allocate(int size)
    {
        if (size <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(size),
                "Размер выделяемого блока должен быть положительным.");
        }

        SortedSet<FreeBlock> candidates = _freeBySize.GetViewBetween(
            new FreeBlock(Offset: 0, Size: size),
            new FreeBlock(Offset: int.MaxValue, Size: int.MaxValue));

        if (candidates.Count == 0)
        {
            throw new OutOfMemoryException(
                $"Невозможно выделить непрерывный блок размером {size} байтов.");
        }

        FreeBlock selected = candidates.Min;
        RemoveFreeBlock(selected);

        var allocated = new MemoryBlock(selected.Offset, size);
        _allocated.Add(allocated.Offset, allocated.Size);

        int remainingSize = selected.Size - size;
        if (remainingSize > 0)
        {
            AddFreeBlock(new FreeBlock(
                checked(selected.Offset + size),
                remainingSize));
        }

        return allocated;
    }

    public void Free(MemoryBlock block)
    {
        if (!_allocated.TryGetValue(block.Offset, out int allocatedSize) ||
            allocatedSize != block.Size)
        {
            throw new InvalidOperationException(
                "Блок не принадлежит аллокатору, уже освобождён или имеет неверный размер.");
        }

        _allocated.Remove(block.Offset);

        int mergedOffset = block.Offset;
        int mergedSize = block.Size;
        FreeBlock? previous = FindPrevious(block.Offset);
        FreeBlock? next = FindNext(block.Offset);

        if (previous is { } previousBlock &&
            checked(previousBlock.Offset + previousBlock.Size) == mergedOffset)
        {
            RemoveFreeBlock(previousBlock);
            mergedOffset = previousBlock.Offset;
            mergedSize = checked(mergedSize + previousBlock.Size);
        }

        if (next is { } nextBlock &&
            checked(mergedOffset + mergedSize) == nextBlock.Offset)
        {
            RemoveFreeBlock(nextBlock);
            mergedSize = checked(mergedSize + nextBlock.Size);
        }

        AddFreeBlock(new FreeBlock(mergedOffset, mergedSize));
    }

    public void Validate()
    {
        if (_freeByOffset.Count != _freeBySize.Count ||
            !_freeByOffset.SetEquals(_freeBySize))
        {
            throw new InvalidOperationException(
                "Индексы свободных блоков рассинхронизированы.");
        }

        int freeSize = 0;
        int previousEnd = 0;

        foreach (FreeBlock block in _freeByOffset)
        {
            if (block.Offset < previousEnd || block.Size <= 0)
            {
                throw new InvalidOperationException(
                    "Обнаружены пересекающиеся или пустые свободные блоки.");
            }

            previousEnd = checked(block.Offset + block.Size);
            freeSize = checked(freeSize + block.Size);
        }

        int allocatedSize = _allocated.Values.Sum();
        if (freeSize + allocatedSize != _totalSize)
        {
            throw new InvalidOperationException(
                "Суммарный размер свободной и занятой памяти не совпадает с общим.");
        }
    }

    private FreeBlock? FindPrevious(int offset)
    {
        SortedSet<FreeBlock> view = _freeByOffset.GetViewBetween(
            new FreeBlock(int.MinValue, 0),
            new FreeBlock(offset - 1, int.MaxValue));

        return view.Count == 0 ? null : view.Max;
    }

    private FreeBlock? FindNext(int offset)
    {
        SortedSet<FreeBlock> view = _freeByOffset.GetViewBetween(
            new FreeBlock(offset + 1, 0),
            new FreeBlock(int.MaxValue, int.MaxValue));

        return view.Count == 0 ? null : view.Min;
    }

    private void AddFreeBlock(FreeBlock block)
    {
        if (!_freeByOffset.Add(block) || !_freeBySize.Add(block))
        {
            throw new InvalidOperationException(
                "Не удалось добавить свободный блок в индексы.");
        }
    }

    private void RemoveFreeBlock(FreeBlock block)
    {
        if (!_freeByOffset.Remove(block) || !_freeBySize.Remove(block))
        {
            throw new InvalidOperationException(
                "Не удалось удалить свободный блок из индексов.");
        }
    }

    private readonly record struct FreeBlock(int Offset, int Size);

    private sealed class FreeBlockSizeComparer : IComparer<FreeBlock>
    {
        public static FreeBlockSizeComparer Instance { get; } = new();

        public int Compare(FreeBlock left, FreeBlock right)
        {
            int sizeComparison = left.Size.CompareTo(right.Size);
            return sizeComparison != 0
                ? sizeComparison
                : left.Offset.CompareTo(right.Offset);
        }
    }

    private sealed class FreeBlockOffsetComparer : IComparer<FreeBlock>
    {
        public static FreeBlockOffsetComparer Instance { get; } = new();

        public int Compare(FreeBlock left, FreeBlock right)
        {
            int offsetComparison = left.Offset.CompareTo(right.Offset);
            return offsetComparison != 0
                ? offsetComparison
                : left.Size.CompareTo(right.Size);
        }
    }
}

public static class RedBlackTreeAllocatorSelfTest
{
    public static void Run()
    {
        var allocator = new RedBlackTreeAllocator(totalSize: 1024);

        MemoryBlock first = allocator.Allocate(128);
        MemoryBlock second = allocator.Allocate(256);
        MemoryBlock third = allocator.Allocate(64);

        Ensure(first == new MemoryBlock(0, 128), "Неверный первый блок.");
        Ensure(second == new MemoryBlock(128, 256), "Неверный второй блок.");
        Ensure(third == new MemoryBlock(384, 64), "Неверный третий блок.");

        allocator.Free(second);
        MemoryBlock bestFit = allocator.Allocate(200);
        Ensure(bestFit.Offset == 128, "Стратегия best fit выбрала неверный блок.");

        allocator.Free(bestFit);
        allocator.Free(first);
        allocator.Free(third);
        allocator.Validate();

        Ensure(allocator.AvailableMemory == 1024, "Не вся память освобождена.");
        Ensure(allocator.LargestFreeBlock == 1024, "Соседние блоки не объединены.");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
