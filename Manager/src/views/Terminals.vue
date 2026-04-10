<template>
  <div class="terminals-container">
    <!-- 左侧：资产分组 -->
    <div class="terminals-sidebar">
      <div class="sidebar-header">
        <span>资产分组</span>
        <div class="header-actions">
          <el-button size="mini" type="text" @click="handleAddGroup">新增</el-button>
          <el-dropdown trigger="click" @command="handleCommand">
            <span class="el-dropdown-link">
              <i class="el-icon-more"></i>
            </span>
            <el-dropdown-menu slot="dropdown">
              <el-dropdown-item command="rename">重命名</el-dropdown-item>
              <el-dropdown-item command="delete">删除</el-dropdown-item>
            </el-dropdown-menu>
          </el-dropdown>
        </div>
      </div>
      <div class="sidebar-content">
        <el-tree
          :data="groupTree"
          :props="treeProps"
          node-key="id"
          default-expand-all
          
          @node-click="handleNodeClick"
        >
          <span slot-scope="{ node, data }" class="tree-node">
            <span class="node-icon">
              <i :class="data.children && data.children.length ? 'el-icon-folder' : 'el-icon-document'"></i>
            </span>
            <span class="node-label">{{ node.label }}</span>
          </span>
        </el-tree>
      </div>
    </div>

    <!-- 右侧：终端列表 -->
    <div class="terminals-main">
      <el-card class="page-card" :body-style="{ padding: '0' }">
        <div slot="header" class="header-row">
          <span>终端列表</span>
          <el-button size="small" type="primary" icon="el-icon-refresh" @click="fetchTerminals">刷新</el-button>
        </div>
        <el-table :data="filteredTerminals" v-loading="loading" stripe style="width: 100%">
          <el-table-column prop="asset_name" label="资产名称" width="140">
            <template slot-scope="scope">
              {{ scope.row.asset_name || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="asset_group" label="资产分组" width="120">
            <template slot-scope="scope">
              {{ scope.row.asset_group || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="hostname" label="主机名称"></el-table-column>
          <el-table-column prop="ip" label="IP地址" width="140"></el-table-column>
          <el-table-column prop="mac" label="MAC地址" width="180">
            <template slot-scope="scope">
              {{ scope.row.mac || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="os" label="操作系统" width="120"></el-table-column>
          <el-table-column prop="status" label="状态" width="100">
            <template slot-scope="scope">
              <el-tag :type="scope.row.status === 'online' ? 'success' : 'info'" size="small">
                {{ scope.row.status === 'online' ? '在线' : '离线' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="cpu_percent" label="CPU利用率" width="100">
            <template slot-scope="scope">
              {{ scope.row.cpu_percent ? scope.row.cpu_percent.toFixed(1) + '%' : '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="memory_percent" label="内存利用率" width="100">
            <template slot-scope="scope">
              {{ scope.row.memory_percent ? scope.row.memory_percent.toFixed(1) + '%' : '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="disk_percent" label="磁盘利用率" width="100">
            <template slot-scope="scope">
              {{ scope.row.disk_percent ? scope.row.disk_percent.toFixed(1) + '%' : '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="last_seen" label="最后活跃时间" width="160"></el-table-column>
          <el-table-column label="操作" width="200">
            <template slot-scope="scope">
              <el-button type="text" size="small" @click="goDetail(scope.row)">详情</el-button>
              <el-button type="text" size="small" @click="handleEdit(scope.row)">编辑</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <!-- 详情/编辑侧边栏 -->
    <el-drawer
      :title="drawerTitle"
      :visible.sync="drawerVisible"
      direction="rtl"
      size="400px"
    >
      <div class="drawer-content" v-if="selectedTerminal">
        <el-form label-width="100px" size="small">
          <el-form-item label="主机名称">
            <span>{{ selectedTerminal.hostname || '-' }}</span>
          </el-form-item>
          <el-form-item label="IP地址">
            <span>{{ selectedTerminal.ip || '-' }}</span>
          </el-form-item>
          <el-form-item label="操作系统">
            <span>{{ selectedTerminal.os }} ({{ selectedTerminal.arch }})</span>
          </el-form-item>
          <el-form-item label="状态">
            <el-tag :type="selectedTerminal.status === 'online' ? 'success' : 'info'" size="small">
              {{ selectedTerminal.status === 'online' ? '在线' : '离线' }}
            </el-tag>
          </el-form-item>
          <el-form-item label="版本">
            <span>{{ selectedTerminal.version || '未知' }}</span>
          </el-form-item>
          <el-form-item label="注册时间">
            <span>{{ formatTime(selectedTerminal.registered_at) }}</span>
          </el-form-item>
          <el-form-item label="最后活跃">
            <span>{{ formatTime(selectedTerminal.last_seen) }}</span>
          </el-form-item>
          <el-form-item label="资产分组">
            <el-select v-if="isEditMode" v-model="selectedTerminal.asset_group" placeholder="请选择资产分组" clearable style="width: 100%">
              <el-option v-for="g in groupOptions" :key="g.id" :label="g.label" :value="g.label"></el-option>
            </el-select>
            <span v-else>{{ selectedTerminal.asset_group || '未分组' }}</span>
          </el-form-item>
          <el-form-item label="资产名称">
            <el-input v-if="isEditMode" v-model="selectedTerminal.asset_name" placeholder="请输入资产名称"></el-input>
            <span v-else>{{ selectedTerminal.asset_name || '未设置' }}</span>
          </el-form-item>
        </el-form>
        <div class="drawer-footer" v-if="isEditMode">
          <el-button type="primary" size="small" @click="saveEdit">保存</el-button>
          <el-button size="small" @click="drawerVisible = false">取消</el-button>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script>
import { getAgentList, getAssetGroups, createAssetGroup, updateAssetGroup, deleteAssetGroup, updateAgentInfo } from '@/utils/api'

export default {
  name: 'Terminals',
  data() {
    return {
      terminals: [],
      loading: false,
      activeGroup: null,
      groupTree: [
        {
          id: 0,
          label: '资产中心',
          children: []
        }
      ],
      treeProps: {
        children: 'children',
        label: 'label'
      },
      groupOptions: [],
      drawerVisible: false,
      drawerTitle: '终端详情',
      isEditMode: false,
      selectedTerminal: null
    }
  },
  computed: {
    onlineCount() {
      return this.terminals.filter(t => t.status === 'online').length
    },
    offlineCount() {
      return this.terminals.filter(t => t.status !== 'online').length
    },
    filteredTerminals() {
      return this.terminals
    }
  },
  mounted() {
    this.fetchTerminals()
    this.fetchGroups()
    this._isMounted = true
  },
  activated() {
    if (this._isMounted && !this._isFetching) {
      this.fetchTerminals()
    }
  },
  beforeDestroy() {
    this._isMounted = false
  },
  methods: {
    fetchTerminals() {
      if (this._isFetching) return
      this._isFetching = true
      this.loading = true
      getAgentList().then(res => {
        if (res && res.data && Array.isArray(res.data)) {
          this.terminals = res.data
        } else if (Array.isArray(res)) {
          this.terminals = res
        } else {
          this.terminals = []
        }
      }).catch(err => {
        console.warn('获取终端列表失败:', err)
      }).finally(() => {
        this.loading = false
        this._isFetching = false
      })
    },
    fetchGroups() {
      getAssetGroups().then(res => {
        if (res && res.data && Array.isArray(res.data)) {
          // 更新分组树
          this.groupTree[0].children = res.data.map(g => ({
            id: g.id,
            label: g.name,
            children: []
          }))
          // 更新下拉选项
          this.groupOptions = res.data.map(g => ({
            id: g.id,
            label: g.name
          }))
        }
      }).catch(err => {
        console.warn('获取分组列表失败:', err)
      })
    },
    handleNodeClick(data) {
      this.activeGroup = data.id
    },
    handleAddGroup() {
      this.$prompt('请输入分组名称', '新增分组', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputPattern: /\S+/,
        inputErrorMessage: '分组名称不能为空'
      }).then(({ value }) => {
        createAssetGroup({ name: value }).then(res => {
          if (res && res.code === 0 && res.data) {
            this.groupTree[0].children.push({
              id: res.data.id,
              label: res.data.name,
              children: []
            })
            this.$message.success('分组已创建')
          } else {
            this.$message.error(res.message || '创建失败')
          }
        }).catch(err => {
          this.$message.error('创建分组失败')
        })
      }).catch(() => {})
    },
    handleCommand(command) {
      if (!this.activeGroup || this.activeGroup === 0) {
        this.$message.warning('请先选择一个分组')
        return
      }
      if (command === 'rename') {
        this.handleRename()
      } else if (command === 'delete') {
        this.handleDelete()
      }
    },
    handleRename() {
      const node = this.findNode(this.groupTree, this.activeGroup)
      if (!node || this.activeGroup === 0) return
      this.$prompt('请输入新的分组名称', '重命名分组', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputValue: node.label,
        inputPattern: /\S+/,
        inputErrorMessage: '分组名称不能为空'
      }).then(({ value }) => {
        updateAssetGroup(this.activeGroup, { name: value }).then(res => {
          if (res && res.code === 0) {
            node.label = value
            this.$message.success('分组已重命名')
          } else {
            this.$message.error(res.message || '重命名失败')
          }
        }).catch(err => {
          this.$message.error('重命名分组失败')
        })
      }).catch(() => {})
    },
    handleDelete() {
      if (this.activeGroup === 0) return
      this.$confirm('确定删除该分组？', '删除确认').then(() => {
        deleteAssetGroup(this.activeGroup).then(res => {
          if (res && res.code === 0) {
            this.removeNode(this.groupTree, this.activeGroup)
            this.activeGroup = null
            this.$message.success('分组已删除')
          } else {
            this.$message.error(res.message || '删除失败')
          }
        }).catch(err => {
          this.$message.error('删除分组失败')
        })
      }).catch(() => {})
    },
    findNode(tree, id) {
      for (const node of tree) {
        if (node.id === id) return node
        if (node.children) {
          const found = this.findNode(node.children, id)
          if (found) return found
        }
      }
      return null
    },
    removeNode(tree, id) {
      for (let i = 0; i < tree.length; i++) {
        if (tree[i].id === id) {
          tree.splice(i, 1)
          return true
        }
        if (tree[i].children) {
          if (this.removeNode(tree[i].children, id)) return true
        }
      }
      return false
    },
    goDetail(row) {
      this.selectedTerminal = { ...row }
      this.drawerTitle = '终端详情'
      this.isEditMode = false
      this.drawerVisible = true
    },
    handleEdit(row) {
      this.selectedTerminal = { ...row }
      this.drawerTitle = '编辑终端'
      this.isEditMode = true
      this.drawerVisible = true
    },
    saveEdit() {
      updateAgentInfo(this.selectedTerminal.id, {
        asset_group: this.selectedTerminal.asset_group || '',
        asset_name: this.selectedTerminal.asset_name || ''
      }).then(res => {
        if (res && res.code === 0) {
          this.$message.success('保存成功')
          this.drawerVisible = false
          this.fetchTerminals()
        } else {
          this.$message.error(res.message || '保存失败')
        }
      }).catch(err => {
        this.$message.error('保存失败')
      })
    },
    formatTime(time) {
      if (!time) return '-'
      const d = new Date(time)
      return `${d.getMonth()+1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
    }
  }
}
</script>

<style scoped>
.terminals-container {
  display: flex;
  height: 100%;
  gap: 2px;
}

.terminals-sidebar {
  width: 14%;
  min-width: 140px;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #e2e8f0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.sidebar-header {
  padding: 0 16px !important;
  height: 48px !important;
  line-height: 48px !important;
  background: #f8fafc !important;
  border-bottom: 1px solid #e2e8f0 !important;
  font-weight: 600 !important;
  font-size: 14px !important;
  color: #1e293b !important;
  display: flex !important;
  justify-content: space-between !important;
  align-items: center !important;
  box-sizing: border-box !important;
  margin: 0 !important;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.header-actions .el-button--text {
  padding: 0;
  color: #6366f1;
  font-size: 12px;
}

.el-dropdown-link {
  cursor: pointer;
  color: #64748b;
  padding: 4px;
}

.el-dropdown-link:hover {
  color: #334155;
}

.sidebar-content {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}

/* 树形连接线样式 */
.sidebar-content {
  flex: 1;
  overflow-y: auto;
  padding: 8px 8px 8px 0;
}

/* 连接线 - 垂直线 */
.sidebar-content .el-tree-node::before {
  content: '';
  position: absolute;
  left: 11px;
  top: -10px;
  bottom: 18px;
  width: 1px;
  background: #d1d5db;
}

/* 连接线 - 水平线 */
.sidebar-content .el-tree-node::after {
  content: '';
  position: absolute;
  left: 11px;
  top: 18px;
  width: 18px;
  height: 1px;
  background: #d1d5db;
}

/* 根节点不需要垂直线上半部分 */
.sidebar-content .el-tree > .el-tree-node::before {
  display: none;
}

/* 最后一个节点垂直线处理 */
.sidebar-content .el-tree-node.is-last-child::before {
  height: 26px;
}

.sidebar-content .el-tree-node__content {
  position: relative;
  padding-left: 0 !important;
}

.sidebar-content .el-tree-node__expand-icon {
  color: #64748b;
  font-size: 12px;
}

.sidebar-content .el-tree-node__expand-icon.is-leaf {
  color: transparent;
}

/* 移除默认缩进 */
.sidebar-content .el-tree-node {
  padding-left: 20px;
  position: relative;
}

.sidebar-content .el-tree-node__children {
  position: relative;
}

.tree-node {
  display: flex;
  align-items: center;
  flex: 1;
}

.node-icon {
  margin-right: 8px;
  color: #64748b;
}

.node-label {
  font-size: 13px;
}

.terminals-main {
  flex: 1;
  overflow: hidden;
}

.page-card {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.page-card .el-card__body {
  padding: 0;
}

.header-row {
  display: flex !important;
  justify-content: space-between !important;
  align-items: center !important;
  padding: 0 16px !important;
  height: 48px !important;
  line-height: 48px !important;
  border-bottom: 1px solid #f1f5f9 !important;
  box-sizing: border-box !important;
  margin: 0 !important;
}

.header-row > span:first-child {
  font-weight: 600 !important;
  font-size: 14px !important;
  color: #1e293b !important;
  margin: 0 !important;
  padding: 0 !important;
}

/* Override el-card header slot */
.page-card >>> .el-card__header {
  padding: 0 16px !important;
  min-height: 48px !important;
  height: 48px !important;
  line-height: 48px !important;
  box-sizing: border-box !important;
  border-bottom: 1px solid #f1f5f9 !important;
}

/* Drawer styles */
.drawer-content {
  padding: 16px;
}
.drawer-footer {
  padding: 16px;
  border-top: 1px solid #eee;
  display: flex;
  gap: 8px;
}
</style>
