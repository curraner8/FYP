import { ref, computed } from 'vue'

export function useDismiss(result) {
  const dismissed = ref(new Set())

  const dismissKey = (file, idx) => `${file}::${idx}`
  const isDismissed = (file, idx) => dismissed.value.has(dismissKey(file, idx))

  const dismiss = (file, idx) => {
    const next = new Set(dismissed.value)
    next.add(dismissKey(file, idx))
    dismissed.value = next
  }

  const undoDismiss = (file, idx) => {
    const next = new Set(dismissed.value)
    next.delete(dismissKey(file, idx))
    dismissed.value = next
  }

  const resetDismissed = () => {
    dismissed.value = new Set()
  }

  const computedScore = computed(() => {
    if (!result.value) return 100
    let penalty = 0
    for (const file of result.value.files) {
      file.findings.forEach((finding, idx) => {
        if (!isDismissed(file.file, idx)) {
          penalty += finding.score_impact
        }
      })
    }
    return Math.max(0, 100 + penalty)
  })

  const computedGrade = computed(() => {
    const s = computedScore.value
    if (s >= 90) return 'A'
    if (s >= 75) return 'B'
    if (s >= 50) return 'C'
    return 'D'
  })

  const activeCount = computed(() => {
    if (!result.value) return 0
    let count = 0
    for (const file of result.value.files) {
      file.findings.forEach((_, idx) => {
        if (!isDismissed(file.file, idx)) count++
      })
    }
    return count
  })

  return {
    isDismissed,
    dismiss,
    undoDismiss,
    resetDismissed,
    computedScore,
    computedGrade,
    activeCount,
  }
}
